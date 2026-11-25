//! The options of `pkey`: what each sets, and what is refused.

use std::ffi::OsString;

use baldssl_core::Error;

use super::{Check, Text, Written, parse_options};

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
        (Written::AsRead, Text::Nothing, Check::Skipped)
    );
}

/// `-noout` wins over `-pubout`; `-pubin` implies `-pubout` and public
/// text, as in OpenSSL's pkey.c.
#[test]
fn implications() {
    assert_eq!(options(&["-pubout"]).written, Written::Public);
    let o = options(&["-pubin", "-text"]);
    assert_eq!((o.written, o.text), (Written::Public, Text::Public));
    assert_eq!(options(&["-pubin", "-noout"]).written, Written::Nothing);
    assert_eq!(options(&["-pubin"]).text, Text::Nothing);
    assert_eq!(options(&["-pubcheck"]).check, Check::Reported);
}

/// The sticky options give the same result in every order: the maximum of
/// what each asks for.
#[test]
fn option_orders() {
    for (orders, written, text) in [
        (
            [["-pubout", "-noout"], ["-noout", "-pubout"]],
            Written::Nothing,
            Text::Nothing,
        ),
        (
            [["-text", "-text_pub"], ["-text_pub", "-text"]],
            Written::AsRead,
            Text::Public,
        ),
        (
            [["-text", "-pubout"], ["-pubout", "-text"]],
            Written::Public,
            Text::AsRead,
        ),
    ] {
        for order in orders {
            let o = options(&order);
            assert_eq!((o.written, o.text), (written, text), "{order:?}");
        }
    }
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
