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
//! numbers and messages by the release line baldssl is built for.
//!
//! Files load as OpenSSL loads them, and those that do not are reported
//! with its loader's lines (see the `load` module). An `-untrusted` file
//! loads when its option is read and each `-CAfile` once all options are,
//! and either failing ends the command with exit code 1 (`Error loading
//! file <file>` for a `-CAfile`, from `setup_verify` in `apps/lib/apps.c`).
//! A certificate to verify that does not load is reported, and the others
//! are still verified, as `check` in `apps/verify.c` does; the command then
//! exits 2.
//!
//! Unlike OpenSSL, baldssl has no default trust store: without `-CAfile`
//! nothing is trusted. Not supported, and reported as such: `-CApath`,
//! `-CAstore`, CRLs, policies and purposes, and the chains
//! [`baldssl_x509::TrustStore::verify`] refuses.

use std::ffi::{OsStr, OsString};

use baldssl_core::{Error, Result, der::syntax::RawTlv};
use baldssl_x509::{
    Certificate, Profile, Reported, TrustStore, Verification, certificate_der,
    certificates_der,
};

use crate::{
    args::{self, Kind, Spec, Unknown},
    input::read_input,
    issuing::unix_now,
    line::{Apps as _, CertificateLoadSummary, Line},
    load::{Credential, LoadFailure, load_line},
    outputs::Outputs,
};

/// The name of the command.
const COMMAND: &str = "verify";

/// The label of standard input in `verify`'s messages (`apps/verify.c`).
const STDIN_LABEL: &str = "stdin";
/// The name of standard input in the loader's messages
/// (`load_key_certs_crls` in `apps/lib/apps.c`).
const STDIN_URI: &str = "<stdin>";
/// How `check` describes a certificate to verify (`apps/verify.c`).
const TARGET_DESC: &str = "certificate file";
/// How `-untrusted` describes its certificates (`apps/verify.c`).
const UNTRUSTED_DESC: &str = "untrusted certificates";
/// What `setup_verify` (`apps/lib/apps.c`) prints before a `-CAfile` that
/// does not load.
const ERROR_LOADING_FILE: &str = "Error loading file";
/// What `load_cert` (`apps/lib/apps.c`) prints before the description of a
/// certificate it could not load, where it does
/// ([`Apps::CERTIFICATE_LOAD_SUMMARY`](crate::line::Apps::CERTIFICATE_LOAD_SUMMARY)).
const UNABLE_TO_LOAD: &str = "Unable to load";

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
/// or does not load (`apps/verify.c`: `ret = 2` unless every certificate
/// verifies).
const VERIFY_FAILED: u8 = 2;

/// The exit code of `openssl verify` when an `-untrusted` or `-CAfile`
/// file does not load: `ret` is still 1, its first value in `apps/verify.c`.
const LOAD_FAILED: u8 = 1;

/// Why a file gave no certificates.
enum Unloaded {
    /// OpenSSL's loader reports it ([`load_line`]).
    Reported(LoadFailure),
    /// Anything else, which baldssl reports as its own error.
    Error(Error),
}

impl From<Error> for Unloaded {
    fn from(e: Error) -> Self {
        Unloaded::Error(e)
    }
}

/// The bytes of `path`, or standard input without one.
fn read(path: Option<&OsStr>) -> core::result::Result<Vec<u8>, Unloaded> {
    match read_input(path) {
        Err(Error::NotFound { .. }) => {
            Err(Unloaded::Reported(LoadFailure::Missing))
        }
        other => Ok(other?),
    }
}

/// Whether `der` decodes as a certificate.
fn decodes(der: &[u8]) -> core::result::Result<(), Unloaded> {
    Certificate::from_der(der)
        .map(|_| ())
        .map_err(|_| Unloaded::Reported(LoadFailure::Undecoded))
}

/// The certificates of a file of them, every one decoding; a file with
/// none, or one that does not decode, does not load, as `load_certs` in
/// `apps/lib/apps.c` refuses it.
fn certificates_of(
    path: &OsStr,
) -> core::result::Result<Vec<RawTlv>, Unloaded> {
    let ders = certificates_der(&read(Some(path))?)
        .map_err(|_| Unloaded::Reported(LoadFailure::Undecoded))?;
    if ders.is_empty() {
        return Err(Unloaded::Reported(LoadFailure::Undecoded));
    }
    for der in &ders {
        decodes(der.as_bytes())?;
    }
    Ok(ders)
}

/// The certificate to verify in `path`, or standard input without one.
/// What baldssl does not read (a `TRUSTED CERTIFICATE`) stays its own
/// error; anything else that does not decode does not load.
fn target_of(path: Option<&OsStr>) -> core::result::Result<Vec<u8>, Unloaded> {
    let der = match certificate_der(&read(path)?, None) {
        Ok(der) => der,
        Err(e @ Error::Unsupported(_)) => return Err(Unloaded::Error(e)),
        Err(_) => return Err(Unloaded::Reported(LoadFailure::Undecoded)),
    };
    decodes(&der)?;
    Ok(der)
}

/// The intermediates in `path`, or the loader's line and exit code 1.
fn load_untrusted(outputs: &mut Outputs, path: &OsStr) -> Result<Vec<RawTlv>> {
    certificates_of(path).map_err(|unloaded| match unloaded {
        Unloaded::Error(e) => e,
        Unloaded::Reported(failure) => {
            outputs.diagnostic(load_line(
                Credential::Certificates,
                UNTRUSTED_DESC,
                &path.to_string_lossy(),
                failure,
            ));
            Error::Reported {
                code: LOAD_FAILED,
                output: Vec::new(),
            }
        }
    })
}

/// The trust anchors in `path`, or `setup_verify`'s line and exit code 1.
fn load_trusted(outputs: &mut Outputs, path: &OsStr) -> Result<Vec<RawTlv>> {
    certificates_of(path).map_err(|unloaded| match unloaded {
        Unloaded::Error(e) => e,
        Unloaded::Reported(_) => {
            outputs.diagnostic(format!(
                "{ERROR_LOADING_FILE} {}",
                path.to_string_lossy()
            ));
            Error::Reported {
                code: LOAD_FAILED,
                output: Vec::new(),
            }
        }
    })
}

/// What OpenSSL prints for a certificate to verify that did not load from
/// `file`: the loader's line, then `load_cert`'s where the release line
/// prints it.
fn target_report(file: &str, failure: LoadFailure) -> String {
    let line = load_line(Credential::Certificate, TARGET_DESC, file, failure);
    match Line::CERTIFICATE_LOAD_SUMMARY {
        CertificateLoadSummary::Printed => {
            format!("{line}\n{UNABLE_TO_LOAD} {TARGET_DESC}\n")
        }
        CertificateLoadSummary::Omitted => format!("{line}\n"),
    }
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
    run_as::<Line>(raw, outputs)
}

/// `verify` as the release line `P` does it.
fn run_as<P>(raw: &[OsString], outputs: &mut Outputs) -> Result<()>
where
    P: Profile,
{
    let (opts, files) =
        args::parse_with_operands(COMMAND, raw, SPECS, Unknown::Refused)?;
    let compat = P::COMPAT;
    let mut trusted_paths = Vec::new();
    let mut untrusted_ders = Vec::new();
    let mut at_time = None;
    for given in opts {
        match given.option {
            Opt::Help => {
                outputs.stdout(args::usage(COMMAND, SPECS));
                return Ok(());
            }
            Opt::CaFile(v) => trusted_paths.push(v),
            Opt::Untrusted(v) => {
                untrusted_ders.extend(load_untrusted(outputs, &v)?);
            }
            Opt::AtTime(v) => at_time = Some(args::intmax(COMMAND, &v)?),
            Opt::CaPath(_) | Opt::CaStore(_) => {
                return Err(Error::unsupported(format!(
                    "{COMMAND} -{}",
                    given.name
                )));
            }
        }
    }
    let mut trusted_ders = Vec::new();
    for path in &trusted_paths {
        trusted_ders.extend(load_trusted(outputs, path)?);
    }
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
        let der = match target_of(path.as_deref()) {
            Ok(der) => der,
            Err(Unloaded::Error(e)) => return Err(e),
            Err(Unloaded::Reported(failure)) => {
                failed = true;
                let file = path
                    .as_ref()
                    .map_or_else(|| STDIN_URI.into(), |p| p.to_string_lossy());
                outputs.stderr(target_report(&file, failure));
                continue;
            }
        };
        let target = Certificate::from_der(&der)?;
        match store.verify::<P>(&target, now)? {
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
                            error.message::<P>()
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
