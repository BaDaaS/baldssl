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
    /// `opt_cipher_any`: a name that is neither an option nor a cipher,
    /// for a command whose unknown options are ciphers (`-aes256`).
    pub(super) const UNKNOWN_OPTION_OR_CIPHER: &str =
        "Unknown option or cipher";
    /// `opt_md`: a name that is neither an option nor a digest, for a
    /// command whose unknown options are digests (`-sha256`).
    pub(super) const UNKNOWN_OPTION_OR_DIGEST: &str =
        "Unknown option or message digest";
    /// `opt_check_rest_arg`: an argument that is not an option.
    pub(super) const EXTRA_OPTION: &str = "Extra option";
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
        Error::Usage(format!(
            "{command}: {} \"{}\" as {kind} number",
            message::CANT_PARSE,
            value.to_string_lossy()
        ))
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
    /// It may name a cipher (`-aes256`), as OpenSSL's `opt_cipher_any`
    /// reads it; baldssl encrypts no key, so it is refused, in those words.
    Ciphers,
    /// It may name a digest (`-sha256`), as OpenSSL's `opt_md` reads it:
    /// the function gives its variant, or `None` to refuse it.
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

/// Parses `args` against `specs`; options not in `specs` go to `unknown`.
///
/// # Errors
///
/// [`Error::Usage`] for an unknown option, a missing value, a value given
/// to a flag, or a positional argument.
pub(crate) fn parse<O>(
    command: &str,
    args: &[OsString],
    specs: &[Spec<O>],
    unknown: Unknown<O>,
) -> Result<Vec<Given<O>>>
where
    O: Clone,
{
    let (opts, operands) = parse_with_operands(command, args, specs, unknown)?;
    match operands.first() {
        Some(arg) => Err(Error::Usage(format!(
            "{command}: {}: \"{}\"",
            message::EXTRA_OPTION,
            arg.to_string_lossy()
        ))),
        None => Ok(opts),
    }
}

/// As [`parse`], also taking arguments that are not options (the files of
/// `verify` and `dgst`). As OpenSSL's `opt_rest`, the options end at the
/// first argument that is not one, or after `--`: everything from there
/// is an operand, even what looks like an option.
///
/// # Errors
///
/// As [`parse`], except for positional arguments.
pub(crate) fn parse_with_operands<O>(
    command: &str,
    args: &[OsString],
    specs: &[Spec<O>],
    unknown: Unknown<O>,
) -> Result<(Vec<Given<O>>, Vec<OsString>)>
where
    O: Clone,
{
    let mut out = Vec::new();
    let mut operands = Vec::new();
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
        let option = match (specs.iter().find(|s| s.name == name), unknown) {
            (Some(spec), _) => match (&spec.kind, inline) {
                (Kind::Value(make), Some(value)) => make(value),
                (Kind::Value(make), None) => {
                    make(it.next().cloned().ok_or_else(|| {
                        Error::Usage(format!(
                            "{command}: Option -{name} {}",
                            message::NEEDS_A_VALUE
                        ))
                    })?)
                }
                (Kind::Flag(option), None) => option.clone(),
                (Kind::Flag(_), Some(_)) => {
                    return Err(Error::Usage(format!(
                        "{command}: Option -{name} {}",
                        message::TAKES_NO_VALUE
                    )));
                }
            },
            (None, Unknown::Refused) => {
                return Err(Error::Usage(format!(
                    "{command}: {}: -{name}",
                    message::UNKNOWN_OPTION
                )));
            }
            (None, Unknown::Ciphers) => {
                return Err(Error::Usage(format!(
                    "{command}: {}: {name}",
                    message::UNKNOWN_OPTION_OR_CIPHER
                )));
            }
            (None, Unknown::Digests(digest)) => match (inline, digest(&name)) {
                (None, Some(option)) => option,
                (Some(_) | None, _) => {
                    return Err(Error::Usage(format!(
                        "{command}: {}: {name}",
                        message::UNKNOWN_OPTION_OR_DIGEST
                    )));
                }
            },
        };
        out.push(Given { name, option });
    }
    Ok((out, operands))
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
                format!("verify: Can't parse \"{v}\" as {kind} number")
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

    #[test]
    fn errors() {
        for bad in [&["-in"][..], &["-bogus"], &["file"], &["-text=1"], &["-"]]
        {
            assert!(
                matches!(
                    parse("x", &os(bad), SPECS, Unknown::Refused),
                    Err(Error::Usage(_))
                ),
                "{bad:?}"
            );
        }
        assert_eq!(
            parse("x", &os(&["-bogus"]), SPECS, Unknown::Refused).err(),
            Some(Error::Usage("x: Unknown option: -bogus".into()))
        );
        assert_eq!(
            parse("x", &os(&["-md2"]), SPECS, Unknown::Digests(|_| None)).err(),
            Some(Error::Usage(
                "x: Unknown option or message digest: md2".into()
            ))
        );
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
