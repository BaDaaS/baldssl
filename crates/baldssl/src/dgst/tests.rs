//! What `dgst` prints, and how its options combine. The digests are the
//! FIPS 180-4 examples for "abc"; the output formats are those the interop
//! tests compare with OpenSSL.

use std::ffi::OsString;

use baldssl_core::Error;
use baldssl_crypto::hash::Algorithm;
use baldssl_x509::Compat;

use super::{
    Encoding, EscapedName, KeyRole, Labels, Operation, Options, Separator,
    parse_options, prepare,
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
    (key_type, digest): (Option<&str>, Option<&str>),
    file: &str,
) -> String {
    let mut out = Vec::new();
    let result = Algorithm::Sha256.digest(b"abc");
    let labels = Labels { key_type, digest };
    o.print(&mut out, &result, Encoding::Hex, labels, file);
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
    assert_eq!(
        EscapedName::new("ab"),
        EscapedName {
            text: "ab".into(),
            escaped: false
        }
    );
    let mut out = Vec::new();
    let none = Labels {
        key_type: None,
        digest: None,
    };
    plain.print(&mut out, b"\x01\x02", Encoding::Binary, none, "f");
    assert_eq!(out, [1, 2]);
}

/// The last of `-c` and `-r`, and of `-hex` and `-binary`, wins.
#[test]
fn last_wins() {
    assert_eq!(options(&["-r", "-c"]).separator, Separator::Colons);
    assert_eq!(options(&["-c", "-r"]).separator, Separator::Coreutils);
    assert_eq!(options(&["-binary", "-hex"]).encoding, Some(Encoding::Hex));
    assert_eq!(
        options(&["-hex", "-binary"]).encoding,
        Some(Encoding::Binary)
    );
    let o = options(&["-sign", "a", "-verify", "b"]);
    assert_eq!(o.role, Some(KeyRole::Verify));
    assert_eq!(o.key_file, Some("b".into()));
    // The flags OpenSSL sets are sticky: -sign after -verify still
    // verifies, with a public key; -prverify after -verify too.
    let o = options(&["-verify", "a", "-sign", "b"]);
    assert_eq!(o.role, Some(KeyRole::Verify));
    assert_eq!(
        options(&["-verify", "a", "-prverify", "b"]).role,
        Some(KeyRole::Verify)
    );
    assert_eq!(
        options(&["-prverify", "a", "-sign", "b"]).role,
        Some(KeyRole::PrVerify)
    );
}

/// The digest named prints as OpenSSL fetched it, OpenSSL's built-in
/// default as `SHA256`, and a key without a digest as its default fetched.
#[test]
fn digest_labels() {
    assert_eq!(
        options(&[]).digest_label_opt(&Operation::Digest),
        Some("SHA256")
    );
    assert_eq!(
        options(&["-sha384"]).digest_label_opt(&Operation::Digest),
        Some("SHA2-384")
    );
    assert_eq!(
        options(&[]).digest_label_opt(&Operation::Hmac(Vec::new())),
        Some("SHA256")
    );
    let preset = parse_options("sha1", Algorithm::from_name_opt("sha1"), &[])
        .unwrap()
        .unwrap();
    assert_eq!(preset.digest_label_opt(&Operation::Digest), Some("SHA1"));
}

/// The checks before any input is read, in OpenSSL's order.
#[test]
fn checks() {
    let refused = |v: &[&str]| {
        matches!(
            prepare("dgst", &options(v), Compat::V3),
            Err(Error::Reported { code: 1, .. })
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
