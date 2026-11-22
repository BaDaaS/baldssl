//! The options of `pkey`: what each sets, and what is refused.

use std::ffi::OsString;

use baldssl_core::Error;

use super::{Text, Written, parse_options};

fn os(v: &[&str]) -> Vec<OsString> {
    v.iter().map(OsString::from).collect()
}

fn options(v: &[&str]) -> super::Options {
    parse_options(&os(v)).unwrap().unwrap()
}

#[test]
fn defaults() {
    let o = options(&[]);
    assert_eq!(
        (o.written, o.text, o.check),
        (Written::AsRead, Text::Nothing, false)
    );
}

/// `-noout` wins over `-pubout`; `-pubin` implies `-pubout` and public
/// text, as in OpenSSL's pkey.c.
#[test]
fn implications() {
    assert_eq!(options(&["-pubout"]).written, Written::Public);
    assert_eq!(options(&["-pubout", "-noout"]).written, Written::Nothing);
    let o = options(&["-pubin", "-text"]);
    assert_eq!((o.written, o.text), (Written::Public, Text::Public));
    assert_eq!(options(&["-text_pub"]).text, Text::Public);
    assert_eq!(options(&["-text_pub", "-text"]).text, Text::Public);
    assert!(options(&["-pubcheck"]).check);
}

#[test]
fn refused() {
    for option in [&["-passin", "pass:x"][..], &["-traditional"]] {
        assert!(
            matches!(parse_options(&os(option)), Err(Error::Unsupported(_))),
            "{option:?}"
        );
    }
    assert!(matches!(
        parse_options(&os(&["-outform", "XML"])),
        Err(Error::Usage(_))
    ));
    assert!(parse_options(&os(&["-help"])).unwrap().is_none());
}
