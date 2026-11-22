//! The options of `req`: what each sets, and what is refused.

use std::ffi::OsString;

use baldssl_core::Error;
use baldssl_crypto::Algorithm as Digest;
use baldssl_x509::InputEncoding;

use baldssl_core::der::TimeKind;

use super::{Mode, Output, Product, parse_options};
use crate::issuing::SerialSource;

fn os(v: &[&str]) -> Vec<OsString> {
    v.iter().map(OsString::from).collect()
}

fn options(v: &[&str]) -> super::Options {
    parse_options(&os(v)).unwrap().unwrap()
}

#[test]
fn defaults() {
    let o = options(&[]);
    assert_eq!(o.mode, Mode::Read);
    assert_eq!(o.output, Output::Pem);
    assert_eq!(o.encoding, InputEncoding::Latin1);
    assert!(!o.verify);
    assert_eq!(o.digest, None);
}

#[test]
fn creating() {
    let o = options(&[
        "-new", "-key", "k.pem", "-subj", "/CN=x", "-utf8", "-sha384",
    ]);
    assert_eq!(o.mode, Mode::Create);
    assert_eq!(o.encoding, InputEncoding::Utf8);
    assert_eq!(o.digest, Some(Digest::Sha384));
    assert_eq!(o.subj, Some(OsString::from("/CN=x")));
}

/// `-noout` wins over `-outform`, in either order.
#[test]
fn noout_wins() {
    assert_eq!(options(&["-outform", "DER"]).output, Output::Der);
    assert_eq!(
        options(&["-noout", "-outform", "DER"]).output,
        Output::Nothing
    );
    assert_eq!(
        options(&["-outform", "DER", "-noout"]).output,
        Output::Nothing
    );
}

#[test]
fn help() {
    assert!(parse_options(&os(&["-help"])).unwrap().is_none());
}

/// What is not supported says so, and SHA-1 is not a request digest here.
#[test]
fn refused() {
    assert_eq!(
        parse_options(&os(&["-text"])).err(),
        Some(Error::unsupported("req -text"))
    );
    assert_eq!(
        parse_options(&os(&["-x509", "-in", "r.pem"])).err(),
        Some(Error::unsupported("req -x509 -in"))
    );
    assert_eq!(
        parse_options(&os(&["-x509", "-verify"])).err(),
        Some(Error::unsupported("req -x509 -verify"))
    );
    assert_eq!(
        parse_options(&os(&["-newkey", "ec"])).err(),
        Some(Error::unsupported("req -newkey"))
    );
    assert_eq!(
        parse_options(&os(&["-sha1"])).err(),
        Some(Error::unsupported("req: digest sha1"))
    );
    assert!(matches!(
        parse_options(&os(&["-outform", "XML"])),
        Err(Error::Usage(_))
    ));
}

/// `-x509` implies `-new`, and its options set the certificate's fields.
#[test]
fn certificates() {
    let o = options(&["-x509"]);
    assert_eq!((o.mode, o.product), (Mode::Create, Product::Certificate));
    assert_eq!(o.lifetime.days, 30);
    assert_eq!(o.serial, SerialSource::Random);
    let o = options(&[
        "-x509",
        "-days",
        "365",
        "-set_serial",
        "0x0102",
        "-not_before",
        "261122000000Z",
        "-not_after",
        "20500101000000Z",
    ]);
    assert_eq!(o.lifetime.days, 365);
    assert!(
        matches!(&o.serial, SerialSource::Given(s) if s.as_be_bytes() == [1, 2])
    );
    let before = o.lifetime.not_before.unwrap();
    assert_eq!((before.kind, before.year), (TimeKind::Utc, 2026));
    let after = o.lifetime.not_after.unwrap();
    assert_eq!((after.kind, after.year), (TimeKind::Generalized, 2050));
    // A GeneralizedTime before 2050 is written as a UTCTime.
    let o = options(&["-x509", "-not_before", "20261122000000Z"]);
    assert_eq!(o.lifetime.not_before.unwrap().kind, TimeKind::Utc);
}

#[test]
fn certificate_rejections() {
    for args in [
        &["-x509", "-days", "-1"][..],
        &["-x509", "-days", "x"],
        &["-x509", "-set_serial", "0xg"],
        &["-x509", "-set_serial", ""],
        &["-x509", "-not_before", "2026"],
        &["-x509", "-not_before", "20261122000000.5Z"],
        &["-x509", "-not_after", "261332000000Z"],
    ] {
        assert!(
            matches!(parse_options(&os(args)), Err(Error::Usage(_))),
            "{args:?}"
        );
    }
    // Zero, and 20 bytes with the top bit set: 21 octets once encoded.
    for serial in ["0", "0x00", "0x8000000000000000000000000000000000000000"] {
        assert!(
            matches!(
                parse_options(&os(&["-x509", "-set_serial", serial])),
                Err(Error::Unsupported(_))
            ),
            "{serial}"
        );
    }
}
