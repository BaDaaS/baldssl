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
