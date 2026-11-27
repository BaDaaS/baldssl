//! `baldssl verify`: verify certificate chains, like `openssl verify`.
//!
//! Supported: the certificates to verify as arguments (PEM or DER; standard
//! input without one), `-CAfile` (trust anchors, PEM files of any number of
//! certificates; repeatable), `-untrusted` (intermediates, likewise) and
//! `-attime` (the time to check validity at, in seconds since the epoch,
//! read as OpenSSL's `opt_intmax` reads numbers; the last one given, and
//! the current time without one).
//! Each certificate that verifies prints `<file>: OK`; one that does not
//! prints, on standard error as OpenSSL does, the subject of the
//! certificate at fault, `error <n> at <depth> depth lookup: <message>`,
//! and `error <file>: verification failed`, and the command exits 2. The
//! checks are those of [`baldssl_x509::TrustStore::verify`], with OpenSSL's error
//! numbers and messages by the release line `BALDSSL_OPENSSL_COMPAT` names.
//!
//! Unlike OpenSSL, baldssl has no default trust store: without `-CAfile`
//! nothing is trusted. Not supported, and reported as such: `-CApath`,
//! `-CAstore`, CRLs, policies and purposes, and the chains
//! [`baldssl_x509::TrustStore::verify`] refuses.

use std::ffi::OsString;

use baldssl_core::{Error, Result, der::syntax::RawTlv};
use baldssl_x509::{
    Certificate, Reported, TrustStore, Verification, certificate_der,
    certificates_der,
};

use crate::{
    args::{self, Kind, Spec, Unknown},
    input::{compat, read_input},
    issuing::unix_now,
    outputs::Outputs,
};

/// The name of the command.
const COMMAND: &str = "verify";

/// The label of standard input in `verify`'s messages (`apps/verify.c`).
const STDIN_LABEL: &str = "stdin";

/// An option of `baldssl verify`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Opt {
    /// `-help`.
    Help,
    /// `-CAfile`.
    CaFile(OsString),
    /// `-untrusted`.
    Untrusted(OsString),
    /// `-attime`.
    AtTime(OsString),
    /// `-CApath`.
    CaPath(OsString),
    /// `-CAstore`.
    CaStore(OsString),
}

/// Every option `baldssl verify` accepts.
pub(crate) const SPECS: &[Spec<Opt>] = &[
    Spec {
        name: "help",
        kind: Kind::Flag(Opt::Help),
        help: "Display this summary",
    },
    Spec {
        name: "CAfile",
        kind: Kind::Value(Opt::CaFile),
        help: "A file of trusted certificates",
    },
    Spec {
        name: "untrusted",
        kind: Kind::Value(Opt::Untrusted),
        help: "A file of untrusted (intermediate) certificates",
    },
    Spec {
        name: "attime",
        kind: Kind::Value(Opt::AtTime),
        help: "Verification time, in seconds since the epoch",
    },
    Spec {
        name: "CApath",
        kind: Kind::Value(Opt::CaPath),
        help: "A directory of trusted certificates (not supported)",
    },
    Spec {
        name: "CAstore",
        kind: Kind::Value(Opt::CaStore),
        help: "A store of trusted certificates (not supported)",
    },
];

/// The exit code of `openssl verify` when a certificate does not verify
/// (`apps/verify.c`: `ret = 2` unless every certificate verifies).
const VERIFY_FAILED: u8 = 2;

/// The certificates of every file named, in order.
fn load_all(paths: &[OsString]) -> Result<Vec<RawTlv>> {
    let mut out = Vec::new();
    for path in paths {
        out.extend(certificates_der(&read_input(Some(path))?)?);
    }
    Ok(out)
}

/// Parses DER certificates.
fn parse_all(ders: &[RawTlv]) -> Result<Vec<Certificate<'_>>> {
    ders.iter()
        .map(|d| Certificate::from_der(d.as_bytes()))
        .collect()
}

/// Verifies each certificate named, and records what `verify` writes.
///
/// # Errors
///
/// Usage errors, unreadable files, what baldssl cannot check, and
/// [`Error::Reported`] with exit code 2 when a certificate does not
/// verify, as OpenSSL exits.
pub(crate) fn run(raw: &[OsString], outputs: &mut Outputs) -> Result<()> {
    let (opts, files) =
        args::parse_with_operands(COMMAND, raw, SPECS, Unknown::Refused)?;
    let mut trusted_paths = Vec::new();
    let mut untrusted_paths = Vec::new();
    let mut at_time = None;
    for given in opts {
        match given.option {
            Opt::Help => {
                outputs.stdout(args::usage(COMMAND, SPECS));
                return Ok(());
            }
            Opt::CaFile(v) => trusted_paths.push(v),
            Opt::Untrusted(v) => untrusted_paths.push(v),
            Opt::AtTime(v) => at_time = Some(args::intmax(COMMAND, &v)?),
            Opt::CaPath(_) | Opt::CaStore(_) => {
                return Err(Error::unsupported(format!(
                    "{COMMAND} -{}",
                    given.name
                )));
            }
        }
    }
    let compat = compat()?;
    let trusted_ders = load_all(&trusted_paths)?;
    let untrusted_ders = load_all(&untrusted_paths)?;
    let trusted = parse_all(&trusted_ders)?;
    let untrusted = parse_all(&untrusted_ders)?;
    let store = TrustStore::new(&trusted, &untrusted)?;
    let now = match at_time {
        Some(seconds) => seconds,
        None => i64::try_from(unix_now()?)
            .map_err(|_| Error::invalid("the system clock is past 64 bits"))?,
    };
    let targets: Vec<Option<OsString>> = if files.is_empty() {
        vec![None]
    } else {
        files.into_iter().map(Some).collect()
    };
    let mut out = Vec::new();
    let mut failed = false;
    for path in targets {
        let label = path.as_ref().map_or_else(
            || STDIN_LABEL.into(),
            |p| p.to_string_lossy().into_owned(),
        );
        let der = certificate_der(&read_input(path.as_deref())?, None)?;
        let target = Certificate::from_der(&der)?;
        match store.verify(&target, now, compat)? {
            Verification::Verified(_) => {
                out.extend_from_slice(format!("{label}: OK\n").as_bytes());
            }
            Verification::Failed(failure) => {
                failed = true;
                let mut report = Vec::new();
                for Reported { error, depth } in &failure.errors {
                    // An error at a depth past the chain built is about
                    // the certificate being verified.
                    let cert =
                        failure.chain.get(*depth).copied().unwrap_or(&target);
                    report
                        .extend(cert.subject.to_openssl(compat.name_style())?);
                    report.extend_from_slice(
                        format!(
                            "\nerror {} at {depth} depth lookup: {}\n",
                            error.code(),
                            error.message(compat)
                        )
                        .as_bytes(),
                    );
                }
                report.extend_from_slice(
                    format!("error {label}: verification failed\n").as_bytes(),
                );
                outputs.stderr(report);
            }
        }
    }
    if failed {
        // What verified is still printed.
        return Err(Error::Reported {
            code: VERIFY_FAILED,
            output: out,
        });
    }
    outputs.stdout(out);
    Ok(())
}

#[cfg(test)]
mod tests;
