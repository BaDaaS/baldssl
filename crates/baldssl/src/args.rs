//! OpenSSL-style option parsing.
//!
//! OpenSSL's `opt_next` accepts `-name`, `--name` and `-name=value`, and an
//! option's value is the next argument even if it starts with `-`. Options
//! are returned in command-line order because some commands (`x509`) print
//! in that order.
//!
//! Each command declares its options as an enum and a table of [`Spec`]s,
//! one per option, pairing its name with its variant: the name is written
//! once, and the command matches the parsed variants exhaustively.

#[cfg(unix)]
use std::os::unix::ffi::OsStrExt as _;
#[cfg(all(target_os = "wasi", target_env = "p1"))]
use std::os::wasi::ffi::OsStrExt as _;
use std::{
    ffi::{OsStr, OsString},
    fmt::Write as _,
};

use baldssl_core::{Error, Result};
use baldssl_x509::{Compat, ExtraOperands, UndeclaredOptions};

use crate::input::compat;

/// The messages of OpenSSL's option parser, `apps/lib/opt.c`, after the
/// command name and a colon.
mod message {
    /// `opt_next`: an option of kind `-` given `-name=value`.
    pub(super) const TAKES_NO_VALUE: &str = "does not take a value";
    /// `opt_next`: an option that takes a value, last on the line.
    pub(super) const NEEDS_A_VALUE: &str = "needs a value";
    /// `opt_next`: a name no option has, for a command without digest
    /// options.
    pub(super) const UNKNOWN_OPTION: &str = "Unknown option";
    /// `opt_md`: a name that is neither an option nor a digest, for a
    /// command whose unknown options are digests (`-sha256`).
    pub(super) const UNKNOWN_OPTION_OR_DIGEST: &str =
        "Unknown option or message digest";
    /// `opt_check_rest_arg`: an argument that is not an option.
    pub(super) const EXTRA_OPTION: &str = "Extra option";
    /// `opt_check_rest_arg`: an argument that is not an option, after an
    /// undeclared one.
    pub(super) const EXTRA_UNKNOWN_OPTIONS: &str = "Extra (unknown) options";
    /// `opt_next`: a second undeclared option, between the word for what
    /// the application reads them as and the two names.
    pub(super) const MULTIPLE: (&str, &str) =
        ("Multiple", "or unknown options");
    /// What a digest application calls an undeclared option
    /// (`opt_set_unknown_name`).
    pub(super) const DIGEST: &str = "digest";
    /// What a cipher application calls an undeclared option
    /// (`opt_set_unknown_name`).
    pub(super) const CIPHER: &str = "cipher";
    /// The line every OpenSSL application ends a usage error with, after
    /// its name and a colon (the `opthelp:` label of each `apps/*.c`).
    pub(super) const USE_HELP: &str = "Use -help for summary.";
    /// `opt_number_error`: a value `opt_intmax` refuses, before the value
    /// quoted.
    pub(super) const CANT_PARSE: &str = "Can't parse";
    /// `opt_number_error`: the base a refused value names by its first
    /// characters, tried in this order.
    pub(super) const NUMBER_BASES: [(&str, &str); 3] = [
        ("0x", "a hexadecimal"),
        ("0X", "a hexadecimal"),
        ("0", "an octal"),
    ];
    /// `opt_number_error`: a refused value without one of those prefixes.
    pub(super) const A_NUMBER: &str = "a";
}

/// The white-space characters of the POSIX ("C") locale, which
/// `strtoimax` skips before a number: space, tab, newline, vertical tab,
/// form feed and carriage return ([POSIX.1-2024, XBD section
/// 7.3.1][lc-ctype], the `space` class).
///
/// [lc-ctype]: https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/V1_chap07.html#tag_07_03_01
const C_SPACE: &[u8] = b" \t\n\x0b\x0c\r";

/// A signed number, as OpenSSL's `opt_intmax` (`apps/lib/opt.c`) reads an
/// option's value: `strtoimax` in base 0, so C white space and a sign,
/// then hexadecimal after `0x` or `0X`, octal after `0`, decimal
/// otherwise; all of the value read, and no overflow of 64 bits. The value
/// is read as bytes, as OpenSSL reads it.
///
/// # Errors
///
/// [`Error::Usage`] with `opt_number_error`'s message, which names the base
/// by the value's first characters.
pub(crate) fn intmax(command: &str, value: &OsStr) -> Result<i64> {
    let bytes = value.as_encoded_bytes();
    strtoimax_opt(bytes).ok_or_else(|| {
        let kind = message::NUMBER_BASES
            .iter()
            .find(|(prefix, _)| bytes.starts_with(prefix.as_bytes()))
            .map_or(message::A_NUMBER, |(_, kind)| kind);
        opthelp(
            command,
            Some(&format!(
                "{} \"{}\" as {kind} number",
                message::CANT_PARSE,
                value.to_string_lossy()
            )),
        )
    })
}

/// A usage error as OpenSSL's applications end one (`goto opthelp`): the
/// line saying what is wrong, if there is one, then `<command>: Use -help
/// for summary.`. The `<command>: ` before the first line is the one every
/// error gets when it is printed.
pub(crate) fn opthelp(command: &str, line: Option<&str>) -> Error {
    Error::Usage(match line {
        Some(line) => format!("{line}\n{command}: {}", message::USE_HELP),
        None => message::USE_HELP.into(),
    })
}

/// `strtoimax(s, &end, 0)`, when it reads the whole of `s` without
/// overflow: C white space, an optional sign, then digits of the base the
/// prefix selects (`0x` only when a hexadecimal digit follows, as
/// `strtoimax` reads `"0x"` as a zero followed by an `x`).
fn strtoimax_opt(s: &[u8]) -> Option<i64> {
    let start = s.iter().position(|b| !C_SPACE.contains(b))?;
    let s = s.get(start..)?;
    let (negative, s) = match s.split_first() {
        Some((b'-', rest)) => (true, rest),
        Some((b'+', rest)) => (false, rest),
        Some(_) | None => (false, s),
    };
    let hex = s.strip_prefix(b"0x").or_else(|| s.strip_prefix(b"0X"));
    let (base, digits) = match hex {
        Some(rest) if rest.first().is_some_and(u8::is_ascii_hexdigit) => {
            (16, rest)
        }
        Some(_) | None if s.starts_with(b"0") => (8, s),
        Some(_) | None => (10, s),
    };
    // Digits of the base are ASCII, so the conversion to text cannot fail
    // on what is left; an empty or foreign digit is refused here.
    if digits.is_empty()
        || !digits.iter().all(|&b| char::from(b).is_digit(base))
    {
        return None;
    }
    let magnitude =
        u64::from_str_radix(core::str::from_utf8(digits).ok()?, base).ok()?;
    if negative {
        0i64.checked_sub_unsigned(magnitude)
    } else {
        i64::try_from(magnitude).ok()
    }
}

/// What an option is: a flag, or an option that takes a value, given as
/// the variant it parses to.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Kind<O> {
    /// `-text`: the variant.
    Flag(O),
    /// `-in <file>`: the variant holding the value.
    Value(fn(OsString) -> O),
}

/// One accepted option.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Spec<O> {
    /// The name without dashes.
    pub name: &'static str,
    /// Flag or value, and the variant.
    pub kind: Kind<O>,
    /// One line for `-help`.
    pub help: &'static str,
}

/// What a command does with an option its table does not name.
#[derive(Debug)]
pub(crate) enum Unknown<O> {
    /// It is refused (`Unknown option: -name`).
    Refused,
    /// It may name a cipher (`-aes256`), read once the options are, as
    /// OpenSSL's `opt_cipher_any` reads it; baldssl encrypts no key, so it
    /// is refused, in OpenSSL's words.
    Ciphers,
    /// It may name a digest (`-sha256`), read once the options are, as
    /// OpenSSL's `opt_md` reads it: the function gives its variant, or
    /// `None` to refuse it.
    Digests(fn(&str) -> Option<O>),
}

// Derived, these would ask `O: Copy`, which a function pointer does not need.
impl<O> Clone for Unknown<O> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<O> Copy for Unknown<O> {}

/// A parsed option occurrence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Given<O> {
    /// The name as typed, without dashes (case preserved, so `-SHA256`
    /// stays `SHA256`).
    pub name: String,
    /// What it parsed to, its value included.
    pub option: O,
}

/// `bytes` as an argument: the bytes themselves where arguments are bytes
/// (Unix and WASI preview 1), and only UTF-8 elsewhere, where the standard
/// library offers no stable, safe way to build an `OsString` from part of
/// another.
#[cfg_attr(
    any(unix, all(target_os = "wasi", target_env = "p1")),
    allow(
        clippy::unnecessary_wraps,
        reason = "None only off Unix and WASI preview 1"
    )
)]
fn os_string_opt(bytes: &[u8]) -> Option<OsString> {
    #[cfg(any(unix, all(target_os = "wasi", target_env = "p1")))]
    {
        Some(OsStr::from_bytes(bytes).to_os_string())
    }
    #[cfg(not(any(unix, all(target_os = "wasi", target_env = "p1"))))]
    {
        std::str::from_utf8(bytes).ok().map(OsString::from)
    }
}

/// Splits `arg` into an option name (dashes removed) and an inline value.
/// The name must be UTF-8; the value is taken as bytes, as OpenSSL takes
/// it, so `-subj=<bytes>` reads as `-subj <bytes>` does.
fn split_option_opt(arg: &OsStr) -> Option<(String, Option<OsString>)> {
    let bytes = arg.as_encoded_bytes();
    let body = bytes
        .strip_prefix(b"--")
        .or_else(|| bytes.strip_prefix(b"-"))?;
    if body.is_empty() {
        return None;
    }
    match body.iter().position(|&b| b == b'=') {
        Some(at) => {
            let (name, rest) = body.split_at(at);
            let value = os_string_opt(rest.get(1..)?)?;
            Some((std::str::from_utf8(name).ok()?.to_string(), Some(value)))
        }
        None => Some((std::str::from_utf8(body).ok()?.to_string(), None)),
    }
}

/// The option a command line gives that the application does not declare,
/// which a digest or cipher application reads once the others are.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Undeclared {
    /// Its name, without dashes.
    name: String,
    /// The value given with `=`, which no digest or cipher takes.
    inline: Option<OsString>,
    /// How many options came before it, where it goes once read.
    at: usize,
}

/// A command line read against its options: the options in order, the
/// operands, and the undeclared option, which the caller checks in its
/// application's order ([`Parsed::check_no_operands`],
/// [`Parsed::into_options`], [`Parsed::split`]).
#[derive(Debug)]
#[must_use]
pub(crate) struct Parsed<O> {
    /// The options, in command-line order.
    options: Vec<Given<O>>,
    /// The arguments from the first that is not an option.
    operands: Vec<OsString>,
    /// What the application makes of an undeclared option.
    unknown: Unknown<O>,
    /// The undeclared option: one, as from OpenSSL 3.2 a second is refused
    /// when read, and OpenSSL 3.0 keeps the last.
    undeclared: Option<Undeclared>,
    /// The release line whose messages are given.
    compat: Compat,
}

impl<O> Parsed<O> {
    /// OpenSSL's error when there are operands (`opt_check_rest_arg`):
    /// `Extra option: "<operand>"`, or `Extra (unknown) options: "<name>"
    /// "<operand>"` after an undeclared option; in OpenSSL 3.0, the hint
    /// alone ([`baldssl_x509::Compat::extra_operands`]).
    ///
    /// # Errors
    ///
    /// [`Error::Usage`] for an operand.
    pub(crate) fn check_no_operands(&self, command: &str) -> Result<()> {
        let Some(operand) = self.operands.first() else {
            return Ok(());
        };
        let line = match self.compat.extra_operands() {
            ExtraOperands::HintOnly => return Err(opthelp(command, None)),
            ExtraOperands::Named => match &self.undeclared {
                None => format!(
                    "{}: \"{}\"",
                    message::EXTRA_OPTION,
                    operand.to_string_lossy()
                ),
                Some(undeclared) => format!(
                    "{}: \"{}\" \"{}\"",
                    message::EXTRA_UNKNOWN_OPTIONS,
                    undeclared.name,
                    operand.to_string_lossy()
                ),
            },
        };
        Err(opthelp(command, Some(&line)))
    }

    /// The options and operands, the undeclared option read as the
    /// application reads it ([`Pending::read`]).
    ///
    /// # Errors
    ///
    /// As [`Pending::read`].
    pub(crate) fn into_options(
        self,
        command: &str,
    ) -> Result<(Vec<Given<O>>, Vec<OsString>)> {
        let (mut options, operands, pending) = self.split();
        pending.read(command, &mut options)?;
        Ok((options, operands))
    }

    /// The declared options, the operands, and the undeclared option, for
    /// an application that reads it after checks of its own (`genpkey`
    /// reads its algorithm first).
    pub(crate) fn split(self) -> (Vec<Given<O>>, Vec<OsString>, Pending<O>) {
        let Parsed {
            options,
            operands,
            unknown,
            undeclared,
            compat,
        } = self;
        (
            options,
            operands,
            Pending {
                unknown,
                undeclared,
                compat,
            },
        )
    }
}

/// The undeclared option of a command line, to be read once the declared
/// ones are, as a digest or cipher application reads it.
#[derive(Debug)]
#[must_use]
pub(crate) struct Pending<O> {
    /// What the application makes of it.
    unknown: Unknown<O>,
    /// The option, if one was given.
    undeclared: Option<Undeclared>,
    /// The release line whose messages are given.
    compat: Compat,
}

impl<O> Pending<O> {
    /// Reads the undeclared option: a digest goes to its place among
    /// `options`; anything else is OpenSSL's error.
    ///
    /// # Errors
    ///
    /// [`Error::Usage`] for an undeclared option that is not a digest the
    /// application takes; baldssl encrypts no key, so a cipher application
    /// refuses every one ([`baldssl_x509::Compat::unknown_cipher_message`]).
    pub(crate) fn read(
        self,
        command: &str,
        options: &mut Vec<Given<O>>,
    ) -> Result<()> {
        let Some(Undeclared { name, inline, at }) = self.undeclared else {
            return Ok(());
        };
        let line = match self.unknown {
            // Refused when read, so never recorded.
            Unknown::Refused => {
                format!("{}: -{name}", message::UNKNOWN_OPTION)
            }
            Unknown::Ciphers => {
                format!("{}: {name}", self.compat.unknown_cipher_message())
            }
            Unknown::Digests(digest) => match (inline, digest(&name)) {
                (None, Some(option)) => {
                    options.insert(at, Given { name, option });
                    return Ok(());
                }
                (Some(_) | None, _) => {
                    format!("{}: {name}", message::UNKNOWN_OPTION_OR_DIGEST)
                }
            },
        };
        Err(opthelp(command, Some(&line)))
    }
}

impl<O> Unknown<O> {
    /// What OpenSSL calls the undeclared options of an application
    /// (`opt_set_unknown_name`), in `Multiple <it> or unknown options`.
    fn noun(self) -> &'static str {
        match self {
            Unknown::Refused | Unknown::Digests(_) => message::DIGEST,
            Unknown::Ciphers => message::CIPHER,
        }
    }
}

/// Parses `args` against `specs`, without operands; options not in `specs`
/// are what `unknown` says.
///
/// # Errors
///
/// [`Error::Usage`] with OpenSSL's lines, in OpenSSL's order: a missing
/// value, a value given to a flag or a refused option as it is read, then
/// an operand, then the undeclared option.
pub(crate) fn parse<O>(
    command: &str,
    args: &[OsString],
    specs: &[Spec<O>],
    unknown: Unknown<O>,
) -> Result<Vec<Given<O>>>
where
    O: Clone,
{
    let parsed = parse_line(command, args, specs, unknown)?;
    parsed.check_no_operands(command)?;
    Ok(parsed.into_options(command)?.0)
}

/// As [`parse`], also taking arguments that are not options (the files of
/// `verify` and `dgst`).
///
/// # Errors
///
/// As [`parse`], except for operands.
pub(crate) fn parse_with_operands<O>(
    command: &str,
    args: &[OsString],
    specs: &[Spec<O>],
    unknown: Unknown<O>,
) -> Result<(Vec<Given<O>>, Vec<OsString>)>
where
    O: Clone,
{
    parse_line(command, args, specs, unknown)?.into_options(command)
}

/// Reads a command line as OpenSSL's `opt_next` does, and as `opt_rest`:
/// the options end at the first argument that is not one, or after `--`,
/// and everything from there is an operand, even what looks like an
/// option. The checks of operands and of the undeclared option are left to
/// the caller, which makes them in its application's order.
///
/// # Errors
///
/// [`Error::Usage`] for a missing value, a value given to a flag, an
/// undeclared option when `unknown` is [`Unknown::Refused`], and, from
/// OpenSSL 3.2, a second undeclared option
/// ([`baldssl_x509::Compat::undeclared_options`]).
pub(crate) fn parse_line<O>(
    command: &str,
    args: &[OsString],
    specs: &[Spec<O>],
    unknown: Unknown<O>,
) -> Result<Parsed<O>>
where
    O: Clone,
{
    parse_line_as(command, args, specs, unknown, compat()?)
}

/// As [`parse_line`], with the messages of the release line `compat`.
///
/// # Errors
///
/// As [`parse_line`].
fn parse_line_as<O>(
    command: &str,
    args: &[OsString],
    specs: &[Spec<O>],
    unknown: Unknown<O>,
    compat: Compat,
) -> Result<Parsed<O>>
where
    O: Clone,
{
    let mut options = Vec::new();
    let mut operands = Vec::new();
    let mut undeclared: Option<Undeclared> = None;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        if arg == "--" {
            operands.extend(it.cloned());
            break;
        }
        let Some((name, inline)) = split_option_opt(arg) else {
            operands.push(arg.clone());
            operands.extend(it.cloned());
            break;
        };
        let Some(spec) = specs.iter().find(|s| s.name == name) else {
            match (unknown, &undeclared, compat.undeclared_options()) {
                (Unknown::Refused, _, _) => {
                    let line = format!("{}: -{name}", message::UNKNOWN_OPTION);
                    return Err(opthelp(command, Some(&line)));
                }
                (
                    Unknown::Ciphers | Unknown::Digests(_),
                    Some(first),
                    UndeclaredOptions::OneOnly,
                ) => {
                    let (multiple, unknown_options) = message::MULTIPLE;
                    let line = format!(
                        "{multiple} {} {unknown_options}: -{} and -{name}",
                        unknown.noun(),
                        first.name
                    );
                    return Err(opthelp(command, Some(&line)));
                }
                (
                    Unknown::Ciphers | Unknown::Digests(_),
                    Some(_) | None,
                    UndeclaredOptions::LastKept | UndeclaredOptions::OneOnly,
                ) => {
                    undeclared = Some(Undeclared {
                        name,
                        inline,
                        at: options.len(),
                    });
                }
            }
            continue;
        };
        let option = match (&spec.kind, inline) {
            (Kind::Value(make), Some(value)) => make(value),
            (Kind::Value(make), None) => {
                make(it.next().cloned().ok_or_else(|| {
                    let line =
                        format!("Option -{name} {}", message::NEEDS_A_VALUE);
                    opthelp(command, Some(&line))
                })?)
            }
            (Kind::Flag(option), None) => option.clone(),
            (Kind::Flag(_), Some(_)) => {
                let line =
                    format!("Option -{name} {}", message::TAKES_NO_VALUE);
                return Err(opthelp(command, Some(&line)));
            }
        };
        options.push(Given { name, option });
    }
    Ok(Parsed {
        options,
        operands,
        unknown,
        undeclared,
        compat,
    })
}

/// The `-help` text.
#[must_use]
pub(crate) fn usage<O>(command: &str, specs: &[Spec<O>]) -> String {
    let mut s = format!("Usage: baldssl {command} [options]\n");
    for spec in specs {
        let arg = match spec.kind {
            Kind::Flag(_) => "",
            Kind::Value(_) => " val",
        };
        // Writing to a String cannot fail.
        let _ = writeln!(
            s,
            " -{:<20} {}",
            format!("{}{arg}", spec.name),
            spec.help
        );
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Values OpenSSL 3.5.9 and 4.1.0 accept and refuse for `verify
    /// -attime`, with the message each refusal prints.
    #[test]
    fn intmax_known_answers() {
        for (v, n) in [
            ("0", 0),
            ("010", 8),
            ("-0x10", -16),
            (" +0x1f", 31),
            ("\t5", 5),
            ("+5", 5),
            ("9223372036854775807", i64::MAX),
            ("-9223372036854775808", i64::MIN),
            ("-0x8000000000000000", i64::MIN),
        ] {
            assert_eq!(intmax("verify", OsStr::new(v)).unwrap(), n, "{v:?}");
        }
        for (v, kind) in [
            ("abc", "a"),
            ("12x", "a"),
            ("", "a"),
            ("5 ", "a"),
            ("-08", "a"),
            (" 08", "a"),
            ("++5", "a"),
            ("9223372036854775808", "a"),
            ("99999999999999999999", "a"),
            ("08", "an octal"),
            ("0x", "a hexadecimal"),
            ("0X1g", "a hexadecimal"),
        ] {
            let Err(Error::Usage(m)) = intmax("verify", OsStr::new(v)) else {
                panic!("{v:?} accepted");
            };
            assert_eq!(
                m,
                format!(
                    "Can't parse \"{v}\" as {kind} number\nverify: Use -help \
                     for summary."
                )
            );
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Opt {
        In(OsString),
        Text,
        Digest,
    }

    const SPECS: &[Spec<Opt>] = &[
        Spec {
            name: "in",
            kind: Kind::Value(Opt::In),
            help: "",
        },
        Spec {
            name: "text",
            kind: Kind::Flag(Opt::Text),
            help: "",
        },
    ];

    fn os(v: &[&str]) -> Vec<OsString> {
        v.iter().map(OsString::from).collect()
    }

    fn options(v: &[&str]) -> Vec<Opt> {
        parse("x", &os(v), SPECS, Unknown::Refused)
            .unwrap()
            .into_iter()
            .map(|g| g.option)
            .collect()
    }

    #[test]
    fn forms() {
        assert_eq!(
            options(&["-in", "a", "--text", "-in=b"]),
            [Opt::In("a".into()), Opt::Text, Opt::In("b".into())]
        );
        // A value may start with a dash, as in OpenSSL.
        assert_eq!(options(&["-in", "-text"]), [Opt::In("-text".into())]);
        let digests =
            Unknown::Digests(|n| (n == "SHA256").then_some(Opt::Digest));
        let given = parse("x", &os(&["-SHA256"]), SPECS, digests).unwrap();
        assert_eq!(
            given,
            [Given {
                name: "SHA256".into(),
                option: Opt::Digest
            }]
        );
    }

    /// The line before the hint at `-help`, as OpenSSL prints it: from
    /// 3.2, and in 3.0 where it differs.
    struct Case {
        args: &'static [&'static str],
        unknown: Unknown<Opt>,
        from_32: &'static str,
        v30: Option<&'static str>,
    }

    /// OpenSSL's lines, in OpenSSL's order: option syntax as it is read,
    /// then an operand, then the undeclared option, worded by what the
    /// application makes of it.
    fn error_cases() -> [Case; 13] {
        let digest =
            Unknown::Digests(|name| (name == "sha256").then_some(Opt::Text));
        [
            Case {
                args: &["-in"],
                unknown: Unknown::Refused,
                from_32: "Option -in needs a value",
                v30: None,
            },
            Case {
                args: &["-text=1"],
                unknown: Unknown::Refused,
                from_32: "Option -text does not take a value",
                v30: None,
            },
            Case {
                args: &["-bogus"],
                unknown: Unknown::Refused,
                from_32: "Unknown option: -bogus",
                v30: None,
            },
            Case {
                args: &["-bogus"],
                unknown: digest,
                from_32: "Unknown option or message digest: bogus",
                v30: None,
            },
            Case {
                args: &["-sha256=1"],
                unknown: digest,
                from_32: "Unknown option or message digest: sha256",
                v30: None,
            },
            Case {
                args: &["-bogus"],
                unknown: Unknown::Ciphers,
                from_32: "Unknown option or cipher: bogus",
                v30: Some("Unknown cipher: bogus"),
            },
            Case {
                args: &["file"],
                unknown: digest,
                from_32: "Extra option: \"file\"",
                v30: Some(""),
            },
            Case {
                args: &["-"],
                unknown: digest,
                from_32: "Extra option: \"-\"",
                v30: Some(""),
            },
            // Option syntax as it is read, before the undeclared option.
            Case {
                args: &["-bogus", "-in"],
                unknown: digest,
                from_32: "Option -in needs a value",
                v30: None,
            },
            Case {
                args: &["-bogus", "-text=1"],
                unknown: digest,
                from_32: "Option -text does not take a value",
                v30: None,
            },
            // An operand before the undeclared option.
            Case {
                args: &["-bogus", "file"],
                unknown: digest,
                from_32: "Extra (unknown) options: \"bogus\" \"file\"",
                v30: Some(""),
            },
            // A second undeclared option, even a digest: refused from 3.2,
            // the last kept in 3.0.
            Case {
                args: &["-sha256", "-bogus"],
                unknown: digest,
                from_32: "Multiple digest or unknown options: -sha256 and -bogus",
                v30: Some("Unknown option or message digest: bogus"),
            },
            Case {
                args: &["-a", "-b"],
                unknown: Unknown::Ciphers,
                from_32: "Multiple cipher or unknown options: -a and -b",
                v30: Some("Unknown cipher: b"),
            },
        ]
    }

    #[test]
    fn errors() {
        let cases = error_cases();
        for compat in Compat::ALL {
            for case in &cases {
                let line = match (compat.undeclared_options(), case.v30) {
                    (UndeclaredOptions::LastKept, Some(v30)) => v30,
                    (UndeclaredOptions::LastKept, None)
                    | (UndeclaredOptions::OneOnly, _) => case.from_32,
                };
                let expected = match line {
                    "" => "Use -help for summary.".to_string(),
                    line => format!("{line}\nx: Use -help for summary."),
                };
                let got = parse_line_as(
                    "x",
                    &os(case.args),
                    SPECS,
                    case.unknown,
                    compat,
                )
                .and_then(|p| {
                    p.check_no_operands("x")?;
                    p.into_options("x")
                });
                assert_eq!(
                    got.err(),
                    Some(Error::Usage(expected)),
                    "{compat:?} {:?}",
                    case.args
                );
            }
        }
    }

    /// A digest is read in its place among the options; in 3.0 the last
    /// undeclared option is the one read; and operands are the caller's to
    /// check.
    #[test]
    fn undeclared_digests() {
        let digest =
            Unknown::Digests(|name| (name == "sha256").then_some(Opt::Text));
        for (compat, args) in [
            (Compat::V4, &["-in", "a", "-sha256", "-text"][..]),
            (Compat::V30, &["-in", "a", "-bogus", "-sha256", "-text"]),
        ] {
            let (o, rest) =
                parse_line_as("x", &os(args), SPECS, digest, compat)
                    .unwrap()
                    .into_options("x")
                    .unwrap();
            let names: Vec<&str> = o.iter().map(|g| g.name.as_str()).collect();
            assert_eq!(names, ["in", "sha256", "text"], "{compat:?}");
            assert_eq!(rest, Vec::<OsString>::new());
        }
        // Operands are the caller's to check.
        assert!(
            parse_line_as(
                "x",
                &os(&["-in", "a", "f"]),
                SPECS,
                digest,
                Compat::V4
            )
            .unwrap()
            .into_options("x")
            .is_ok()
        );
        assert_eq!(opthelp("x", None).to_string(), "Use -help for summary.");
    }

    /// The help lists every option, a value option with ` val`.
    #[test]
    fn help() {
        let text = usage("x", SPECS);
        assert!(text.starts_with("Usage: baldssl x [options]\n"));
        assert!(text.contains(" -in val"));
        assert!(text.contains(" -text "));
    }

    /// An inline value is taken as bytes: `-in=<bytes>` gives what
    /// `-in <bytes>` gives, UTF-8 or not.
    #[cfg(unix)]
    #[test]
    fn inline_values_are_bytes() {
        let value = OsStr::from_bytes(b"/CN=\xe9t\xe9").to_os_string();
        let mut inline = OsString::from("-in=");
        inline.push(&value);
        assert_eq!(
            parse("x", &[inline], SPECS, Unknown::Refused).unwrap()[0].option,
            Opt::In(value.clone())
        );
        let separate = vec![OsString::from("-in"), value.clone()];
        assert_eq!(
            parse("x", &separate, SPECS, Unknown::Refused).unwrap()[0].option,
            Opt::In(value)
        );
    }

    /// The options end at the first operand, or after `--`.
    #[test]
    fn operands() {
        let (o, rest) = parse_with_operands(
            "x",
            &os(&["-text", "a", "-in", "b"]),
            SPECS,
            Unknown::Refused,
        )
        .unwrap();
        assert_eq!(o.len(), 1);
        assert_eq!(rest, os(&["a", "-in", "b"]));
        let (o, rest) = parse_with_operands(
            "x",
            &os(&["--", "-text"]),
            SPECS,
            Unknown::Refused,
        )
        .unwrap();
        assert_eq!(o, []);
        assert_eq!(rest, os(&["-text"]));
    }

    proptest! {
        /// Every 64-bit number reads back from its decimal, hexadecimal and
        /// octal spellings, with any sign and leading white space.
        #[test]
        fn intmax_reads_every_spelling(n in any::<i64>(), ws in "[ \t\n]{0,2}") {
            let m = n.unsigned_abs();
            let sign = if n < 0 { "-" } else { "" };
            for body in [format!("{m}"), format!("0x{m:x}"), format!("0X{m:X}"),
                format!("0{m:o}")] {
                let v = format!("{ws}{sign}{body}");
                prop_assert_eq!(intmax("x", OsStr::new(&v)).ok(), Some(n));
            }
            if n >= 0 {
                let v = format!("+{n}");
                prop_assert_eq!(intmax("x", OsStr::new(&v)).ok(), Some(n));
            }
        }

        /// Trailing characters, and magnitudes past 64 bits, are refused.
        #[test]
        fn intmax_refuses(n in any::<i64>(), tail in "[ g.x-]{1,3}",
                over in (1u64 << 63)..=u64::MAX) {
            let v = format!("{n}{tail}");
            prop_assert!(intmax("x", OsStr::new(&v)).is_err());
            let v = format!("{over}");
            prop_assert!(intmax("x", OsStr::new(&v)).is_err());
            let v = format!("-{}", u128::from(over) + 1);
            prop_assert!(intmax("x", OsStr::new(&v)).is_err());
        }

        /// Order and multiplicity of flags are preserved.
        #[test]
        fn preserves_order(flags in prop::collection::vec(prop::bool::ANY, 0..20)) {
            let args: Vec<OsString> = flags
                .iter()
                .flat_map(|&t| if t { vec!["-text"] } else { vec!["-in", "f"] })
                .map(OsString::from)
                .collect();
            let opts = parse("x", &args, SPECS, Unknown::Refused).unwrap();
            let got: Vec<bool> =
                opts.iter().map(|o| matches!(o.option, Opt::Text)).collect();
            prop_assert_eq!(got, flags);
        }
    }
}
