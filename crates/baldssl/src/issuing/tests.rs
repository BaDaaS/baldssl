//! Serials, times and serial files.

use std::ffi::OsStr;

use baldssl_core::{
    Error,
    der::TimeKind,
    hex::{self, Case},
};

use super::{
    SerialSource, default_serial_file, increment, parse_serial, parse_time,
};

#[test]
fn serials() {
    let s = |v: &str| parse_serial("x", OsStr::new(v));
    assert_eq!(s("258").unwrap().as_be_bytes(), [1, 2]);
    assert_eq!(s("0x0102").unwrap().as_be_bytes(), [1, 2]);
    assert_eq!(s("0XfF").unwrap().as_be_bytes(), [0xff]);
    for bad in ["", "0x", "12a", "0xg", "-1"] {
        assert!(matches!(s(bad), Err(Error::Usage(_))), "{bad}");
    }
    // Zero, and 20 bytes with the top bit set: 21 octets once encoded.
    for refused in ["0", "0x00", "0x8000000000000000000000000000000000000000"] {
        assert!(
            matches!(s(refused), Err(Error::Unsupported(_))),
            "{refused}"
        );
    }
}

#[test]
fn times() {
    let t = |v: &str| parse_time("x", "not_before", OsStr::new(v));
    let utc = t("261122000000Z").unwrap();
    assert_eq!((utc.kind(), utc.year()), (TimeKind::Utc, 2026));
    // A GeneralizedTime before 2050 is written as a UTCTime.
    assert_eq!(t("20261122000000Z").unwrap().kind(), TimeKind::Utc);
    let late = t("20500101000000Z").unwrap();
    assert_eq!((late.kind(), late.year()), (TimeKind::Generalized, 2050));
    for bad in ["2026", "20261122000000.5Z", "261332000000Z", "x"] {
        assert!(matches!(t(bad), Err(Error::Usage(_))), "{bad}");
    }
}

#[test]
fn incrementing() {
    assert_eq!(increment(&[0x0a]), [0x0b]);
    assert_eq!(increment(&[0xff]), [1, 0]);
    assert_eq!(increment(&[1, 0xff, 0xff]), [2, 0, 0]);
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

/// The file is read, incremented, used and written back, as OpenSSL's
/// `x509` does: `0A` gives `0B`, `FF` gives `0100`.
#[test]
fn serial_files() {
    let dir = std::env::temp_dir()
        .join(format!("baldssl-srl-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("ca.srl");
    for (before, after) in [("0A\n", "0B\n"), ("ff", "0100\n")] {
        std::fs::write(&path, before).unwrap();
        let used = SerialSource::File {
            path: path.clone(),
            create: false,
        }
        .next("x")
        .unwrap();
        let written = std::fs::read_to_string(&path).unwrap();
        assert_eq!(written, after);
        assert_eq!(hex::plain(used.as_be_bytes(), Case::Upper) + "\n", written);
    }
    std::fs::remove_file(&path).unwrap();
    let missing = SerialSource::File {
        path: path.clone(),
        create: false,
    };
    assert!(matches!(missing.next("x"), Err(Error::Io { .. })));
    let created = SerialSource::File {
        path: path.clone(),
        create: true,
    }
    .next("x")
    .unwrap();
    // 159 random bits: at most 20 bytes, the top bit clear, and one byte
    // shorter whenever the top 7 bits are all zero.
    let bytes = created.as_be_bytes();
    assert!((1..=20).contains(&bytes.len()));
    assert!(bytes.len() < 20 || bytes.first().is_some_and(|b| *b < 0x80));
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        hex::plain(bytes, Case::Upper) + "\n"
    );
    std::fs::remove_file(&path).unwrap();
    std::fs::remove_dir(&dir).unwrap();
}
