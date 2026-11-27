//! Serials, times and serial files.

use std::ffi::OsStr;

use baldssl_core::{Error, der::TimeKind};
use baldssl_crypto::Algorithm as Digest;
use baldssl_fs::Access;

use super::{
    MissingSerialFile, SerialSource, ValidityTime, default_serial_file,
    set_serial, signing_digest_opt, validity_time,
};
use crate::outputs::{Effect, Outputs};

#[test]
fn serials() {
    let s = |v: &str| set_serial(OsStr::new(v));
    assert_eq!(s("0x0102").unwrap().as_be_bytes(), [1, 2]);
    assert_eq!(
        s("12a").err(),
        Some(Error::Usage("invalid serial number 12a".into()))
    );
    assert!(matches!(s("0"), Err(Error::Unsupported(_))));
}

#[test]
fn times() {
    let t = |v: &str| validity_time("not_before", OsStr::new(v));
    let Ok(ValidityTime::At(utc)) = t("261122000000Z") else {
        panic!("a UTCTime")
    };
    assert_eq!((utc.kind(), utc.year()), (TimeKind::Utc, 2026));
    // A GeneralizedTime before 2050 is written as a UTCTime.
    assert!(
        matches!(t("20261122000000Z"), Ok(ValidityTime::At(t)) if t.kind() == TimeKind::Utc)
    );
    let Ok(ValidityTime::At(late)) = t("20500101000000Z") else {
        panic!("a GeneralizedTime")
    };
    assert_eq!((late.kind(), late.year()), (TimeKind::Generalized, 2050));
    assert_eq!(t("today").unwrap(), ValidityTime::Today);
    for bad in ["2026", "20261122000000.5Z", "261332000000Z", "x", "Today"] {
        assert!(matches!(t(bad), Err(Error::Usage(_))), "{bad}");
    }
}

#[test]
fn default_files() {
    assert_eq!(
        default_serial_file(OsStr::new("ca.crt")),
        OsStr::new("ca.srl")
    );
    assert_eq!(
        default_serial_file(OsStr::new("dir/ca")),
        OsStr::new("dir/ca.srl")
    );
}

/// SHA-1 is the one digest baldssl does not sign with.
#[test]
fn signing_digests() {
    for d in [
        Digest::Sha224,
        Digest::Sha256,
        Digest::Sha384,
        Digest::Sha512,
    ] {
        assert_eq!(signing_digest_opt(d), Some(d));
    }
    assert_eq!(signing_digest_opt(Digest::Sha1), None);
}

/// The file is read and incremented, and its new contents are an effect
/// for `main` to write, as OpenSSL's `x509` saves it; a missing file is
/// an error unless it is to be created.
#[test]
fn serial_files() {
    let dir = std::env::temp_dir()
        .join(format!("baldssl-srl-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("ca.srl");
    std::fs::write(&path, "0A\n").unwrap();
    let mut out = Outputs::default();
    let used = SerialSource::File {
        path: path.clone(),
        missing: MissingSerialFile::Refused,
    }
    .next(&mut out)
    .unwrap();
    assert_eq!(used.as_be_bytes(), [0x0b]);
    assert_eq!(
        out.effects(),
        [Effect::File {
            path: path.clone(),
            access: Access::Default,
            bytes: b"0B\n".to_vec(),
        }]
    );
    std::fs::remove_file(&path).unwrap();
    let mut out = Outputs::default();
    let missing = SerialSource::File {
        path: path.clone(),
        missing: MissingSerialFile::Refused,
    };
    assert!(matches!(missing.next(&mut out), Err(Error::Io { .. })));
    assert_eq!(out.effects(), []);
    let created = SerialSource::File {
        path: path.clone(),
        missing: MissingSerialFile::Created,
    }
    .next(&mut out)
    .unwrap();
    // 159 random bits: at most 20 bytes, the top bit clear, and one byte
    // shorter whenever the top 7 bits are all zero.
    let bytes = created.as_be_bytes();
    assert!((1..=20).contains(&bytes.len()));
    assert!(bytes.len() < 20 || bytes.first().is_some_and(|b| *b < 0x80));
    assert_eq!(
        out.effects(),
        [Effect::File {
            path: path.clone(),
            access: Access::Default,
            bytes: created.to_serial_file().into_bytes(),
        }]
    );
    std::fs::remove_dir(&dir).unwrap();
}
