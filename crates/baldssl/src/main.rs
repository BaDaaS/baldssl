//! `baldssl`: a reimplementation of the `openssl` command-line tool.
//!
//! The first goal is compatibility: the same arguments, the same output
//! bytes. The OpenSSL-compatible commands are a thin layer over the library
//! crates, which hold the primitives. Each command records what it writes
//! (standard output, standard error, files) in an [`outputs::Outputs`], and
//! only `main` writes it, through `baldssl-fs`.
//!
//! Terms, as the commands use them: PKCS#8 (Public-Key Cryptography
//! Standards #8, private keys, [RFC 5958]) and PKCS#10 (certificate
//! requests, [RFC 2986]); EC (elliptic curve) keys, which SEC 1
//! (Standards for Efficient Cryptography 1, [SEC 1]) also encodes; DER
//! (Distinguished Encoding Rules, [X.690]) and PEM (Privacy-Enhanced Mail,
//! [RFC 7468]) encodings; a CA (certificate authority) and the RDNs
//! (relative distinguished names) of a name ([RFC 5280 section 4.1.2.4]).
//!
//! Exit codes: 0 on success, 1 on any error, 2 when an input file is missing.
//!
//! [RFC 5958]: https://www.rfc-editor.org/rfc/rfc5958
//! [RFC 2986]: https://www.rfc-editor.org/rfc/rfc2986
//! [SEC 1]: https://www.secg.org/sec1-v2.pdf
//! [X.690]: https://www.itu.int/rec/T-REC-X.690
//! [RFC 7468]: https://www.rfc-editor.org/rfc/rfc7468
//! [RFC 5280 section 4.1.2.4]: https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.4

mod args;
mod dgst;
mod digest;
mod genpkey;
mod input;
mod issuing;
mod keygen;
mod line;
mod load;
mod outputs;
mod pkey;
mod req;
mod verify;
mod x509;

use std::{ffi::OsString, fmt::Write as _, process::ExitCode, str::FromStr};

use baldssl_core::{Error, Result};
use baldssl_crypto::hash::Algorithm;
use baldssl_x509::Profile;

use crate::outputs::Outputs;

/// A command of `baldssl`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Command {
    /// `dgst`.
    Dgst,
    /// `genpkey`.
    Genpkey,
    /// `help`.
    Help,
    /// `pkey`.
    Pkey,
    /// `req`.
    Req,
    /// `verify`.
    Verify,
    /// `version`.
    Version,
    /// `x509`.
    X509,
    /// A digest shortcut, named after its digest (`sha256` is
    /// `dgst -sha256`), one for each of [`Algorithm::ALL`].
    Digest(Algorithm),
}

/// The other spellings of `help`, as OpenSSL accepts them.
const HELP_ALIASES: [&str; 2] = ["-help", "--help"];

impl Command {
    /// Every command but the digest shortcuts.
    const NAMED: [Command; 8] = [
        Command::Dgst,
        Command::Genpkey,
        Command::Help,
        Command::Pkey,
        Command::Req,
        Command::Verify,
        Command::Version,
        Command::X509,
    ];

    /// Every command, the digest shortcuts included, in the order `help`
    /// lists them: by name.
    fn all() -> Vec<Command> {
        let mut all: Vec<Command> = Command::NAMED
            .into_iter()
            .chain(Algorithm::ALL.into_iter().map(Command::Digest))
            .collect();
        all.sort_by_key(|c| c.name());
        all
    }

    /// The name it is called by.
    fn name(self) -> &'static str {
        match self {
            Command::Dgst => "dgst",
            Command::Genpkey => "genpkey",
            Command::Help => "help",
            Command::Pkey => "pkey",
            Command::Req => "req",
            Command::Verify => "verify",
            Command::Version => "version",
            Command::X509 => "x509",
            Command::Digest(algorithm) => algorithm.name(),
        }
    }

    /// What it does, for `help`.
    fn about(self) -> String {
        match self {
            Command::Dgst => "Hash, MAC, sign and verify files".into(),
            Command::Genpkey => "Generate a private key".into(),
            Command::Help => "List the commands".into(),
            Command::Pkey => "Read, convert, print and check keys".into(),
            Command::Req => {
                "Create, read and verify certificate requests".into()
            }
            Command::Verify => "Verify certificate chains".into(),
            Command::Version => "Print the baldssl version".into(),
            Command::X509 => "Display X.509 certificates".into(),
            Command::Digest(algorithm) => format!(
                "Hash files with {} (dgst -{})",
                algorithm.fetched_name(),
                algorithm.name()
            ),
        }
    }

    /// Runs the command on `args`, recording what it writes in `out`.
    fn run(self, args: &[OsString], out: &mut Outputs) -> Result<()> {
        match self {
            Command::Dgst => dgst::run(self.name(), None, args, out),
            Command::Digest(algorithm) => {
                dgst::run(self.name(), Some(algorithm), args, out)
            }
            Command::Genpkey => genpkey::run(args, out),
            Command::Help => {
                out.stdout(help());
                Ok(())
            }
            Command::Pkey => pkey::run(args, out),
            Command::Req => req::run(args, out),
            Command::Verify => verify::run(args, out),
            Command::Version => {
                out.stdout(format!(
                    "baldssl {}, imitating {} (feature {})\n",
                    env!("CARGO_PKG_VERSION"),
                    <line::Line as Profile>::NAME,
                    <line::Line as Profile>::FEATURE,
                ));
                Ok(())
            }
            Command::X509 => x509::run(args, out),
        }
    }
}

/// A command's name, exactly (`sha256` and not `SHA256`), or one of
/// [`HELP_ALIASES`].
///
/// # Errors
///
/// [`Error::Usage`] with OpenSSL's message for any other name.
impl FromStr for Command {
    type Err = Error;

    fn from_str(name: &str) -> Result<Self> {
        if HELP_ALIASES.contains(&name) {
            return Ok(Command::Help);
        }
        Command::all()
            .into_iter()
            .find(|c| c.name() == name)
            .ok_or_else(|| {
                Error::Usage(format!(
                    "Invalid command '{name}'; type \"help\" for a list."
                ))
            })
    }
}

/// The list of commands.
fn help() -> String {
    let mut s = String::from("Commands:\n");
    for command in Command::all() {
        // Writing to a String cannot fail.
        let _ = writeln!(s, "  {:<10} {}", command.name(), command.about());
    }
    s
}

/// Runs the command `args` names, recording what it writes in `out`.
fn dispatch(args: &[OsString], out: &mut Outputs) -> Result<()> {
    let Some((name, rest)) = args.split_first() else {
        out.stdout(help());
        return Ok(());
    };
    let command: Command = name.to_str().map_or_else(
        || {
            Err(Error::Usage(format!(
                "Invalid command '{}'; type \"help\" for a list.",
                name.to_string_lossy()
            )))
        },
        str::parse,
    )?;
    command.run(rest, out)
}

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let mut out = Outputs::default();
    let (extra, outcome) = match dispatch(&args, &mut out) {
        Ok(()) => (Vec::new(), Ok(ExitCode::SUCCESS)),
        // A command that reported its failure itself adds nothing to
        // standard error; what it had for standard output still goes there.
        Err(Error::Reported { code, output }) => {
            (output, Ok(ExitCode::from(code)))
        }
        Err(e) => (Vec::new(), Err(e)),
    };
    // What the command recorded before failing is written all the same,
    // as OpenSSL had written it by then.
    match out.apply(&extra).and(outcome) {
        Ok(code) => code,
        Err(e) => {
            let command = args
                .first()
                .map_or_else(|| "baldssl".into(), |c| c.to_string_lossy());
            // Nothing more to do if standard error is gone.
            let _ = baldssl_fs::write_stderr(
                format!("{command}: {e}\n").as_bytes(),
            );
            ExitCode::from(e.exit_code())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every command parses back from its name, and `help` from its
    /// aliases; a digest shortcut takes its name exactly.
    #[test]
    fn names() {
        for command in Command::all() {
            assert_eq!(command.name().parse::<Command>().unwrap(), command);
        }
        for algorithm in Algorithm::ALL {
            assert_eq!(
                algorithm.name().parse::<Command>().unwrap(),
                Command::Digest(algorithm)
            );
        }
        for alias in HELP_ALIASES {
            assert_eq!(alias.parse::<Command>().unwrap(), Command::Help);
        }
        for bad in ["bogus", "SHA256"] {
            assert!(matches!(bad.parse::<Command>(), Err(Error::Usage(_))));
        }
    }

    /// `help` lists every command, once, in order.
    #[test]
    fn help_lists_every_command() {
        let listed: Vec<String> = help()
            .lines()
            .skip(1)
            .filter_map(|l| l.split_whitespace().next().map(String::from))
            .collect();
        let names: Vec<&str> =
            Command::all().into_iter().map(Command::name).collect();
        assert_eq!(listed, names);
    }
}
