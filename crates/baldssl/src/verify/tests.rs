//! The options of `verify`, and the files it cannot load.

use std::{
    ffi::{OsStr, OsString},
    path::PathBuf,
};

use baldssl_core::{Error, Result};
use baldssl_x509::Compat;

use super::{
    ERROR_LOADING_FILE, LOAD_FAILED, TARGET_DESC, UNTRUSTED_DESC,
    VERIFY_FAILED, run, target_report,
};
use crate::{
    line::compat,
    load::{Credential, LoadFailure, load_line},
    outputs::Outputs,
};

fn os(v: &[&str]) -> Vec<OsString> {
    v.iter().map(OsString::from).collect()
}

#[test]
fn help_and_refusals() {
    let mut out = Outputs::default();
    run(&os(&["-help"]), &mut out).unwrap();
    assert!(
        String::from_utf8(out.stdout_bytes())
            .unwrap()
            .contains(" -CAfile")
    );
    for option in ["-CApath", "-CAstore"] {
        assert!(
            matches!(
                run(&os(&[option, "x"]), &mut Outputs::default()),
                Err(Error::Unsupported(_))
            ),
            "{option}"
        );
    }
    assert!(matches!(
        run(&os(&["-purpose", "sslserver"]), &mut Outputs::default()),
        Err(Error::Usage(_))
    ));
}

/// A directory of this test's own, and a file in it with `contents`.
fn scratch(test: &str, name: &str, contents: &str) -> PathBuf {
    let dir = std::env::temp_dir()
        .join(format!("baldssl-verify-{test}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join(name);
    std::fs::write(&file, contents).unwrap();
    file
}

fn run_args(args: &[&OsStr]) -> (Result<()>, String) {
    let raw: Vec<OsString> = args.iter().map(|a| a.to_os_string()).collect();
    let mut out = Outputs::default();
    let result = run(&raw, &mut out);
    (result, String::from_utf8(out.stderr_bytes()).unwrap())
}

fn exit_code_opt(result: &Result<()>) -> Option<u8> {
    match result {
        Err(Error::Reported { code, .. }) => Some(*code),
        Ok(()) | Err(_) => None,
    }
}

/// A certificate to verify that does not load is reported with the
/// loader's lines, and the next one is still tried: here a missing file,
/// then one with no certificate, which both end in exit code 2.
#[test]
fn targets_that_do_not_load() {
    let compat = compat();
    let garbage = scratch("targets", "garbage.txt", "not a certificate\n");
    let missing = garbage.with_file_name("missing.pem");
    let (result, stderr) =
        run_args(&[missing.as_os_str(), garbage.as_os_str()]);
    assert_eq!(exit_code_opt(&result), Some(VERIFY_FAILED));
    let expected = [
        target_report(&missing.to_string_lossy(), LoadFailure::Missing, compat),
        target_report(
            &garbage.to_string_lossy(),
            LoadFailure::Undecoded,
            compat,
        ),
    ]
    .concat();
    assert_eq!(stderr, expected);
    std::fs::remove_dir_all(garbage.parent().unwrap()).unwrap();
}

/// `-untrusted` loads when it is read, before `-CAfile`, and ends the
/// command with exit code 1; `-CAfile` reports `setup_verify`'s line.
#[test]
fn intermediates_and_anchors_that_do_not_load() {
    let compat = compat();
    let empty = scratch("lists", "empty.pem", "");
    let missing = empty.with_file_name("missing.pem");
    let (result, stderr) = run_args(&[
        OsStr::new("-CAfile"),
        missing.as_os_str(),
        OsStr::new("-untrusted"),
        empty.as_os_str(),
        OsStr::new("leaf.pem"),
    ]);
    assert_eq!(exit_code_opt(&result), Some(LOAD_FAILED));
    let line = load_line(
        Credential::Certificates,
        UNTRUSTED_DESC,
        &empty.to_string_lossy(),
        LoadFailure::Undecoded,
        compat,
    );
    assert_eq!(stderr, format!("{line}\n"));

    let (result, stderr) = run_args(&[
        OsStr::new("-CAfile"),
        missing.as_os_str(),
        OsStr::new("leaf.pem"),
    ]);
    assert_eq!(exit_code_opt(&result), Some(LOAD_FAILED));
    assert_eq!(
        stderr,
        format!("{ERROR_LOADING_FILE} {}\n", missing.to_string_lossy())
    );
    std::fs::remove_dir_all(empty.parent().unwrap()).unwrap();
}

/// What baldssl does not read stays its own error rather than a file that
/// does not load: a certificate with trust settings.
#[test]
fn unsupported_targets_stay_errors() {
    let trusted = scratch(
        "unsupported",
        "trusted.pem",
        "-----BEGIN TRUSTED CERTIFICATE-----\nAA==\n\
         -----END TRUSTED CERTIFICATE-----\n",
    );
    let (result, stderr) = run_args(&[trusted.as_os_str()]);
    assert!(matches!(result, Err(Error::Unsupported(_))), "{result:?}");
    assert_eq!(stderr, "");
    std::fs::remove_dir_all(trusted.parent().unwrap()).unwrap();
}

/// 3.0's `load_cert` follows the loader's line with "Unable to load"; the
/// other lines do not.
#[test]
fn target_reports_by_release_line() {
    assert_eq!(
        target_report("f", LoadFailure::Undecoded, Compat::V30),
        "Could not read certificate file from f\n\
         Unable to load certificate file\n"
    );
    for compat in [Compat::V3, Compat::V36, Compat::V4] {
        assert_eq!(
            target_report("f", LoadFailure::Undecoded, compat),
            format!(
                "{}\n",
                load_line(
                    Credential::Certificate,
                    TARGET_DESC,
                    "f",
                    LoadFailure::Undecoded,
                    compat
                )
            )
        );
    }
}
