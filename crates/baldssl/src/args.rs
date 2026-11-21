//! OpenSSL-style option parsing.
//!
//! OpenSSL's `opt_next` accepts `-name`, `--name` and `-name=value`, and an
//! option's value is the next argument even if it starts with `-`. Options
//! are returned in command-line order because some commands (`x509`) print
//! in that order.

use std::{
    ffi::{OsStr, OsString},
    fmt::Write as _,
};

use baldssl_core::{Error, Result};

/// Whether an option takes a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    /// `-text`
    Flag,
    /// `-in <file>`
    Value,
}

/// One accepted option.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Spec {
    /// The name without dashes.
    pub name: &'static str,
    /// Flag or value.
    pub kind: Kind,
    /// One line for `-help`.
    pub help: &'static str,
}

/// A parsed option occurrence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Opt {
    /// The name as typed, without dashes (case preserved, so `-SHA256`
    /// stays `SHA256`).
    pub name: String,
    /// The value for [`Kind::Value`] options.
    pub value: Option<OsString>,
}

/// Splits `arg` into an option name (dashes removed) and an inline value.
fn split_option_opt(arg: &OsStr) -> Option<(String, Option<OsString>)> {
    let s = arg.to_str()?;
    let body = s.strip_prefix("--").or_else(|| s.strip_prefix('-'))?;
    if body.is_empty() {
        return None;
    }
    match body.split_once('=') {
        Some((name, value)) => Some((name.to_string(), Some(value.into()))),
        None => Some((body.to_string(), None)),
    }
}

/// Parses `args` against `specs`. Options not in `specs` are passed to
/// `extra`, which returns whether it accepts them as flags (used for the
/// `-<digest>` family).
///
/// # Errors
///
/// [`Error::Usage`] for an unknown option, a missing value, a value given
/// to a flag, or a positional argument.
pub(crate) fn parse(
    command: &str,
    args: &[OsString],
    specs: &[Spec],
    extra: impl Fn(&str) -> bool,
) -> Result<Vec<Opt>> {
    let mut out = Vec::new();
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        let Some((name, inline)) = split_option_opt(arg) else {
            return Err(Error::Usage(format!(
                "{command}: Extra option: \"{}\"",
                arg.to_string_lossy()
            )));
        };
        match specs.iter().find(|s| s.name == name) {
            Some(spec) if spec.kind == Kind::Value => {
                let value = match inline {
                    Some(v) => v,
                    None => it.next().cloned().ok_or_else(|| {
                        Error::Usage(format!(
                            "{command}: Option -{name} needs a value"
                        ))
                    })?,
                };
                out.push(Opt {
                    name,
                    value: Some(value),
                });
            }
            Some(_) => {
                if inline.is_some() {
                    return Err(Error::Usage(format!(
                        "{command}: Option -{name} does not take a value"
                    )));
                }
                out.push(Opt { name, value: None });
            }
            None if inline.is_none() && extra(&name) => {
                out.push(Opt { name, value: None });
            }
            None => {
                return Err(Error::Usage(format!(
                    "{command}: Unknown option or message digest: {name}"
                )));
            }
        }
    }
    Ok(out)
}

/// The `-help` text.
#[must_use]
pub(crate) fn usage(command: &str, specs: &[Spec]) -> String {
    let mut s = format!("Usage: baldssl {command} [options]\n");
    for spec in specs {
        let arg = match spec.kind {
            Kind::Flag => String::new(),
            Kind::Value => " val".to_string(),
        };
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

    const SPECS: &[Spec] = &[
        Spec {
            name: "in",
            kind: Kind::Value,
            help: "",
        },
        Spec {
            name: "text",
            kind: Kind::Flag,
            help: "",
        },
    ];

    fn os(v: &[&str]) -> Vec<OsString> {
        v.iter().map(OsString::from).collect()
    }

    fn names(opts: &[Opt]) -> Vec<&str> {
        opts.iter().map(|o| o.name.as_str()).collect()
    }

    #[test]
    fn forms() {
        let o =
            parse("x", &os(&["-in", "a", "--text", "-in=b"]), SPECS, |_| false)
                .unwrap();
        assert_eq!(names(&o), ["in", "text", "in"]);
        assert_eq!(o[0].value.as_deref(), Some(OsStr::new("a")));
        assert_eq!(o[2].value.as_deref(), Some(OsStr::new("b")));
        // A value may start with a dash, as in OpenSSL.
        let o = parse("x", &os(&["-in", "-text"]), SPECS, |_| false).unwrap();
        assert_eq!(o[0].value.as_deref(), Some(OsStr::new("-text")));
        let o =
            parse("x", &os(&["-SHA256"]), SPECS, |n| n == "SHA256").unwrap();
        assert_eq!(names(&o), ["SHA256"]);
    }

    #[test]
    fn errors() {
        for bad in [&["-in"][..], &["-bogus"], &["file"], &["-text=1"], &["-"]]
        {
            assert!(
                matches!(
                    parse("x", &os(bad), SPECS, |_| false),
                    Err(Error::Usage(_))
                ),
                "{bad:?}"
            );
        }
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
            let opts = parse("x", &args, SPECS, |_| false).unwrap();
            let got: Vec<bool> = opts.iter().map(|o| o.name == "text").collect();
            prop_assert_eq!(got, flags);
        }
    }
}
