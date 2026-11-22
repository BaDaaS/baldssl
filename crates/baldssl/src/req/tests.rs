//! The options of `req`: what each sets, and what is refused.

use std::ffi::OsString;

use baldssl_core::Error;
use baldssl_crypto::Algorithm as Digest;
use baldssl_x509::InputEncoding;

use super::{Mode, Output, parse_options};

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
    for option in ["-text", "-x509"] {
        assert_eq!(
            parse_options(&os(&[option])).err(),
            Some(Error::unsupported(format!("req {option}")))
        );
    }
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
