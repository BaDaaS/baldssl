//! Byte-for-byte comparison of `baldssl x509` against outputs recorded from
//! real OpenSSL binaries (`scripts/gen-golden.sh`), for both compatibility
//! profiles. Needs no OpenSSL at test time, so it runs on every CI platform.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures")
}

fn baldssl(args: &[&str], compat: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_baldssl"))
        .args(args)
        .env("BALDSSL_OPENSSL_COMPAT", compat)
        .output()
        .expect("spawn baldssl")
}

fn cases() -> Vec<(String, Vec<String>)> {
    fs::read_to_string(fixtures().join("cases.txt"))
        .unwrap()
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            let (name, args) = l.split_once('|').unwrap();
            (
                name.to_string(),
                args.split_whitespace().map(String::from).collect(),
            )
        })
        .collect()
}

fn certs() -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = fs::read_dir(fixtures().join("certs"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "crt"))
        .collect();
    v.sort();
    assert!(!v.is_empty(), "no fixtures");
    v
}

#[test]
fn matches_openssl_golden_files() {
    let mut checked = 0;
    let mut failures = Vec::new();
    for (profile, compat) in [("v3", "3"), ("v4", "4")] {
        for cert in certs() {
            let stem = cert.file_stem().unwrap().to_string_lossy().into_owned();
            for (case, args) in cases() {
                let golden = fixtures()
                    .join("golden")
                    .join(profile)
                    .join(&stem)
                    .join(format!("{case}.out"));
                let want = fs::read(&golden)
                    .unwrap_or_else(|e| panic!("{}: {e}", golden.display()));
                let mut argv = vec!["x509", "-in", cert.to_str().unwrap()];
                argv.extend(args.iter().map(String::as_str));
                let out = baldssl(&argv, compat);
                checked += 1;
                if !out.status.success() || out.stdout != want {
                    failures.push(format!(
                        "{profile}/{stem}/{case}: exit {:?}, stderr {}",
                        out.status.code(),
                        String::from_utf8_lossy(&out.stderr)
                    ));
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {checked} differ:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

fn scratch(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("golden-tests");
    fs::create_dir_all(&dir).unwrap();
    dir.join(name)
}

#[test]
fn exit_codes() {
    let missing = scratch("does-not-exist.crt");
    let out =
        baldssl(&["x509", "-in", missing.to_str().unwrap(), "-noout"], "3");
    assert_eq!(out.status.code(), Some(2), "missing file");

    let garbage = scratch("garbage.bin");
    fs::write(&garbage, [0x30, 0x82, 0xff, 0xff, 0x00]).unwrap();
    let out =
        baldssl(&["x509", "-in", garbage.to_str().unwrap(), "-noout"], "3");
    assert_eq!(out.status.code(), Some(1), "parse error");

    let cert = &certs()[0];
    for bad in [
        &["x509", "-in", cert.to_str().unwrap(), "-nope"][..],
        &["x509", "-in"],
        &["x509", "-in", cert.to_str().unwrap(), "-md5"],
        &["frobnicate"],
    ] {
        assert_eq!(baldssl(bad, "3").status.code(), Some(1), "{bad:?}");
    }
    let out = baldssl(&["x509", "-in", cert.to_str().unwrap(), "-noout"], "9");
    assert_eq!(out.status.code(), Some(1), "bad compat profile");
    assert!(baldssl(&["version"], "3").status.success());
    assert!(baldssl(&["x509", "-help"], "3").status.success());
}

/// PEM written on Windows (CRLF) and DER both decode to the same output.
#[test]
fn input_encodings_agree() {
    let cert = &certs()[0];
    let text = |path: &Path, extra: &[&str]| {
        let mut argv =
            vec!["x509", "-in", path.to_str().unwrap(), "-noout", "-text"];
        argv.extend(extra);
        let out = baldssl(&argv, "3");
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        out.stdout
    };
    let reference = text(cert, &[]);

    let pem = fs::read_to_string(cert).unwrap();
    let crlf = scratch("crlf.crt");
    fs::write(&crlf, pem.replace('\n', "\r\n")).unwrap();
    assert_eq!(text(&crlf, &[]), reference);

    let der = scratch("cert.der");
    let out = baldssl(
        &[
            "x509",
            "-in",
            cert.to_str().unwrap(),
            "-outform",
            "DER",
            "-out",
            der.to_str().unwrap(),
        ],
        "3",
    );
    assert!(out.status.success());
    assert_eq!(text(&der, &[]), reference);
    assert_eq!(text(&der, &["-inform", "DER"]), reference);

    // DER -> PEM reproduces the original PEM (64-column, LF).
    let back = scratch("back.crt");
    let out = baldssl(
        &[
            "x509",
            "-in",
            der.to_str().unwrap(),
            "-out",
            back.to_str().unwrap(),
        ],
        "3",
    );
    assert!(out.status.success());
    assert_eq!(fs::read_to_string(back).unwrap(), pem);
}
