//! The options of `verify`.

use std::ffi::OsString;

use baldssl_core::Error;

use super::run;
use crate::outputs::Outputs;

fn os(v: &[&str]) -> Vec<OsString> {
    v.iter().map(OsString::from).collect()
}

#[test]
fn help_and_refusals() {
    let mut out = Outputs::default();
    run(&os(&["-help"]), &mut out).unwrap();
    assert!(
        String::from_utf8(out.stdout_bytes())
            .unwrap()
            .contains(" -CAfile")
    );
    for option in ["-CApath", "-CAstore"] {
        assert!(
            matches!(
                run(&os(&[option, "x"]), &mut Outputs::default()),
                Err(Error::Unsupported(_))
            ),
            "{option}"
        );
    }
    assert!(matches!(
        run(&os(&["-purpose", "sslserver"]), &mut Outputs::default()),
        Err(Error::Usage(_))
    ));
}
