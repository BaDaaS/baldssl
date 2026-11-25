//! `baldssl`: a reimplementation of the `openssl` command-line tool.
//!
//! The first goal is compatibility: the same arguments, the same output
//! bytes. The OpenSSL-compatible commands are a thin layer over the library
//! crates, which hold the primitives.
//!
//! Exit codes: 0 on success, 1 on any error, 2 when an input file is missing.

mod args;
mod dgst;
mod digest;
mod genpkey;
mod input;
mod issuing;
mod keygen;
mod pkey;
mod req;
mod verify;
mod x509;

use std::{ffi::OsString, fmt::Write as _, path::Path, process::ExitCode};

use baldssl_core::Error;
use baldssl_crypto::hash::Algorithm;
use baldssl_fs::write_output;

const COMMANDS: &[(&str, &str)] = &[
    ("dgst", "Hash, MAC, sign and verify files"),
    ("genpkey", "Generate a private key"),
    ("help", "List the commands"),
    ("pkey", "Read, convert, print and check keys"),
    ("req", "Create, read and verify certificate requests"),
    ("sha1", "Hash files with SHA-1 (dgst -sha1)"),
    ("sha224", "Hash files with SHA-224 (dgst -sha224)"),
    ("sha256", "Hash files with SHA-256 (dgst -sha256)"),
    ("sha384", "Hash files with SHA-384 (dgst -sha384)"),
    ("sha512", "Hash files with SHA-512 (dgst -sha512)"),
    ("verify", "Verify certificate chains"),
    ("version", "Print the baldssl version"),
    ("x509", "Display X.509 certificates"),
];

fn help() -> Vec<u8> {
    let mut s = String::from("Commands:\n");
    for (name, what) in COMMANDS {
        let _ = writeln!(s, "  {name:<10} {what}");
    }
    s.into_bytes()
}

/// The digest a shortcut command names (`sha256` is `dgst -sha256`): the
/// name of one of [`Algorithm::ALL`], exactly.
fn digest_shortcut_opt(name: &str) -> Option<Algorithm> {
    Algorithm::ALL.into_iter().find(|a| a.name() == name)
}

/// Runs one command and returns the bytes to write and where.
fn dispatch(args: &[OsString]) -> Result<(Vec<u8>, Option<OsString>), Error> {
    let Some((command, rest)) = args.split_first() else {
        return Ok((help(), None));
    };
    match command.to_str() {
        Some("dgst") => dgst::render("dgst", None, rest),
        Some(name) if let Some(digest) = digest_shortcut_opt(name) => {
            dgst::render(name, Some(digest), rest)
        }
        Some("genpkey") => genpkey::render(rest),
        Some("pkey") => pkey::render(rest),
        Some("req") => req::render(rest),
        Some("verify") => verify::render(rest),
        Some("x509") => x509::render(rest),
        Some("version") => Ok((
            format!("baldssl {}\n", env!("CARGO_PKG_VERSION")).into_bytes(),
            None,
        )),
        Some("help" | "-help" | "--help") => Ok((help(), None)),
        _ => Err(Error::Usage(format!(
            "Invalid command '{}'; type \"help\" for a list.",
            command.to_string_lossy()
        ))),
    }
}

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let result = dispatch(&args).and_then(|(out, path)| {
        write_output(&out, path.as_deref().map(Path::new))
    });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        // A command that reported its failure itself adds nothing to
        // standard error; what it had for standard output still goes there.
        Err(Error::Reported { code, output }) => {
            match write_output(&output, None) {
                Ok(()) => ExitCode::from(code),
                Err(e) => ExitCode::from(e.exit_code()),
            }
        }
        Err(e) => {
            let command = args
                .first()
                .map_or_else(|| "baldssl".into(), |c| c.to_string_lossy());
            eprintln!("{command}: {e}");
            ExitCode::from(e.exit_code())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{COMMANDS, digest_shortcut_opt};
    use baldssl_crypto::hash::Algorithm;

    /// Every digest has its shortcut, listed among the commands, and the
    /// shortcuts take the names exactly.
    #[test]
    fn digest_shortcuts() {
        for algorithm in Algorithm::ALL {
            assert_eq!(digest_shortcut_opt(algorithm.name()), Some(algorithm));
            assert!(
                COMMANDS.iter().any(|(name, _)| *name == algorithm.name()),
                "{algorithm:?}"
            );
        }
        assert_eq!(digest_shortcut_opt("SHA256"), None);
        assert_eq!(digest_shortcut_opt("dgst"), None);
    }
}
