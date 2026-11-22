//! `baldssl verify`: verify certificate chains, like `openssl verify`.
//!
//! Supported: the certificates to verify as arguments (PEM or DER; standard
//! input without one), `-CAfile` (trust anchors, PEM files of any number of
//! certificates; repeatable) and `-untrusted` (intermediates, likewise).
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

use std::{
    ffi::OsString,
    io::Write as _,
    time::{SystemTime, UNIX_EPOCH},
};

use baldssl_core::{Error, Result, der::syntax::RawTlv};
use baldssl_x509::{
    Certificate, Reported, TrustStore, Verification, certificate_der,
    certificates_der,
};

use crate::{
    args::{self, Kind, Spec},
    input::read_input,
};

/// Every option `baldssl verify` accepts.
pub(crate) const SPECS: &[Spec] = &[
    Spec {
        name: "help",
        kind: Kind::Flag,
        help: "Display this summary",
    },
    Spec {
        name: "CAfile",
        kind: Kind::Value,
        help: "A file of trusted certificates",
    },
    Spec {
        name: "untrusted",
        kind: Kind::Value,
        help: "A file of untrusted (intermediate) certificates",
    },
    Spec {
        name: "CApath",
        kind: Kind::Value,
        help: "A directory of trusted certificates (not supported)",
    },
    Spec {
        name: "CAstore",
        kind: Kind::Value,
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

/// Writes `bytes` on standard error.
fn note(bytes: &[u8]) {
    // Nothing to do if standard error is gone.
    let _ = std::io::stderr().write_all(bytes);
}

/// Verifies each certificate named, and renders what `verify` writes on
/// standard output.
///
/// # Errors
///
/// Usage errors, unreadable files, what baldssl cannot check, and
/// [`Error::Reported`] with exit code 2 when a certificate does not
/// verify, as OpenSSL exits.
pub(crate) fn render(raw: &[OsString]) -> Result<(Vec<u8>, Option<OsString>)> {
    let (opts, files) =
        args::parse_with_operands("verify", raw, SPECS, |_| false)?;
    let mut trusted_paths = Vec::new();
    let mut untrusted_paths = Vec::new();
    for opt in opts {
        let value = opt.value.clone().unwrap_or_default();
        match opt.name.as_str() {
            "help" => {
                return Ok((args::usage("verify", SPECS).into_bytes(), None));
            }
            "CAfile" => trusted_paths.push(value),
            "untrusted" => untrusted_paths.push(value),
            name => return Err(Error::unsupported(format!("verify -{name}"))),
        }
    }
    let compat = crate::x509::compat()?;
    let trusted_ders = load_all(&trusted_paths)?;
    let untrusted_ders = load_all(&untrusted_paths)?;
    let trusted = parse_all(&trusted_ders)?;
    let untrusted = parse_all(&untrusted_ders)?;
    let store = TrustStore::new(&trusted, &untrusted)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
    let targets: Vec<Option<OsString>> = if files.is_empty() {
        vec![None]
    } else {
        files.into_iter().map(Some).collect()
    };
    let mut out = Vec::new();
    let mut failed = false;
    for path in targets {
        let label = path.as_ref().map_or_else(
            || "stdin".into(),
            |p| p.to_string_lossy().into_owned(),
        );
        let der = certificate_der(&read_input(path.as_deref())?, None)?;
        let target = Certificate::from_der(&der)?;
        match store.verify(&target, now)? {
            Verification::Verified(_) => {
                out.extend_from_slice(format!("{label}: OK\n").as_bytes());
            }
            Verification::Failed(failure) => {
                failed = true;
                let mut report = Vec::new();
                for Reported { error, depth } in &failure.errors {
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
                note(&report);
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
    Ok((out, None))
}

#[cfg(test)]
mod tests;
