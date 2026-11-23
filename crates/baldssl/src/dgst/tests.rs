//! What `dgst` prints, and how its options combine. The digests are the
//! FIPS 180-4 examples for "abc"; the output formats are those the interop
//! tests compare with OpenSSL.

use std::ffi::OsString;

use baldssl_core::Error;
use baldssl_crypto::hash::Algorithm;
use baldssl_x509::Compat;

use super::{
    Operation, Options, Separator, digest_label_opt, escape_newlines,
    parse_options, prepare, print,
};

fn os(v: &[&str]) -> Vec<OsString> {
    v.iter().map(OsString::from).collect()
}

fn options(v: &[&str]) -> Options {
    parse_options("dgst", None, &os(v)).unwrap().unwrap()
}

/// SHA-256("abc"), FIPS 180-4 example (NIST CSRC, "Examples with
/// Intermediate Values").
const SHA256_ABC: &str =
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

/// The text line `print` gives.
fn line(
    o: &Options,
    labels: (Option<&str>, Option<&str>),
    file: &str,
) -> String {
    let mut out = Vec::new();
    let digest = Algorithm::Sha256.digest(b"abc");
    print(&mut out, &digest, o, false, labels, file);
    String::from_utf8(out).unwrap()
}

#[test]
fn formats() {
    let plain = options(&[]);
    assert_eq!(
        line(&plain, (None, Some("SHA2-256")), "f"),
        format!("SHA2-256(f)= {SHA256_ABC}\n")
    );
    assert_eq!(
        line(&plain, (Some("EC"), Some("SHA2-256")), "f"),
        format!("EC-SHA2-256(f)= {SHA256_ABC}\n")
    );
    assert_eq!(
        line(&plain, (Some("ED25519"), None), "f"),
        format!("ED25519(f)= {SHA256_ABC}\n")
    );
    assert_eq!(
        line(&plain, (None, None), "f"),
        format!("(f)= {SHA256_ABC}\n")
    );
    let colons = line(&options(&["-c"]), (None, Some("SHA1")), "f");
    assert!(colons.starts_with("SHA1(f)= ba:78:16:bf:"), "{colons}");
    assert_eq!(
        line(&options(&["-c", "-r"]), (Some("EC"), Some("SHA1")), "f"),
        format!("{SHA256_ABC} *f\n")
    );
    // A newline in the name is escaped, and the line marked with a
    // backslash, as coreutils does.
    assert_eq!(
        line(&options(&["-r"]), (None, None), "a\nb"),
        format!("\\{SHA256_ABC} *a\\nb\n")
    );
    assert_eq!(escape_newlines("ab"), ("ab".into(), false));
    let mut out = Vec::new();
    print(&mut out, b"\x01\x02", &plain, true, (None, None), "f");
    assert_eq!(out, [1, 2]);
}

/// The last of `-c` and `-r`, and of `-hex` and `-binary`, wins.
#[test]
fn last_wins() {
    assert_eq!(options(&["-r", "-c"]).separator, Separator::Colons);
    assert_eq!(options(&["-c", "-r"]).separator, Separator::Coreutils);
    assert_eq!(options(&["-binary", "-hex"]).binary, Some(false));
    assert_eq!(options(&["-hex", "-binary"]).binary, Some(true));
    let o = options(&["-sign", "a", "-verify", "b"]);
    assert_eq!((o.verify, o.public_key), (true, true));
    assert_eq!(o.key_file, Some("b".into()));
}

/// The digest named prints as OpenSSL fetched it, OpenSSL's built-in
/// default as `SHA256`, and a key without a digest as its default fetched.
#[test]
fn digest_labels() {
    assert_eq!(
        digest_label_opt(&options(&[]), &Operation::Digest),
        Some("SHA256")
    );
    assert_eq!(
        digest_label_opt(&options(&["-sha384"]), &Operation::Digest),
        Some("SHA2-384")
    );
    assert_eq!(
        digest_label_opt(&options(&[]), &Operation::Hmac(Vec::new())),
        Some("SHA256")
    );
    let preset = parse_options("sha1", Algorithm::from_name_opt("sha1"), &[])
        .unwrap()
        .unwrap();
    assert_eq!(digest_label_opt(&preset, &Operation::Digest), Some("SHA1"));
}

/// The checks before any input is read, in OpenSSL's order.
#[test]
fn checks() {
    let refused = |v: &[&str]| {
        matches!(
            prepare("dgst", &options(v), Compat::V3),
            Err(Error::Reported(1))
        )
    };
    assert!(refused(&["-sign", "k", "a", "b"]));
    assert!(refused(&["-verify", "k"]));
    assert!(refused(&["-hmac", "x", "-sign", "k"]));
    assert!(refused(&["-xoflen", "3"]));
    assert!(matches!(
        parse_options("dgst", None, &os(&["-md5"])),
        Err(Error::Unsupported(_))
    ));
    assert!(matches!(
        parse_options("dgst", None, &os(&["-mac", "x"])),
        Err(Error::Unsupported(_))
    ));
    assert!(matches!(
        parse_options("dgst", None, &os(&["-keyform", "XYZ"])),
        Err(Error::Usage(_))
    ));
}
