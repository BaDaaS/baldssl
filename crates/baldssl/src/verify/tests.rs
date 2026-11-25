//! The options of `verify`.

use std::ffi::OsString;

use baldssl_core::Error;

use super::render;

fn os(v: &[&str]) -> Vec<OsString> {
    v.iter().map(OsString::from).collect()
}

#[test]
fn help_and_refusals() {
    let (help, _) = render(&os(&["-help"])).unwrap();
    assert!(String::from_utf8(help).unwrap().contains(" -CAfile"));
    for option in ["-CApath", "-CAstore"] {
        assert!(
            matches!(render(&os(&[option, "x"])), Err(Error::Unsupported(_))),
            "{option}"
        );
    }
    assert!(matches!(
        render(&os(&["-purpose", "sslserver"])),
        Err(Error::Usage(_))
    ));
}
