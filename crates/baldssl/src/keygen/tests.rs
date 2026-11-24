//! Curve names and `-newkey` values.

use std::ffi::OsStr;

use baldssl_core::Error;
use baldssl_pkey::Algorithm;

use super::KeyParameters;

/// `-newkey` names the algorithm, case-insensitively, and an EC key takes
/// its curve from `-pkeyopt` or from a parameters file.
#[test]
fn newkey_values() {
    let newkey = |v: &str, opts: &[&str]| {
        let mut p = KeyParameters::default();
        p.set_newkey("req", OsStr::new(v))?;
        for o in opts {
            p.pkeyopt("req", OsStr::new(o))?;
        }
        p.algorithm("req")
    };
    assert_eq!(newkey("ed25519", &[]).unwrap(), Algorithm::Ed25519);
    assert_eq!(newkey("ED25519", &[]).unwrap(), Algorithm::Ed25519);
    assert_eq!(
        newkey(
            "ec",
            &["ec_paramgen_curve:P-384", "ec_param_enc:named_curve"]
        )
        .unwrap(),
        Algorithm::P384
    );
    assert_eq!(
        newkey("ec", &["group:prime256v1"]).unwrap(),
        Algorithm::P256
    );
    assert!(matches!(newkey("ec", &[]), Err(Error::Usage(_))));
    // Ed25519 is an algorithm, not a curve EC parameters name.
    assert!(matches!(
        newkey("ec", &["ec_paramgen_curve:ed25519"]),
        Err(Error::Unsupported(_))
    ));
    assert!(matches!(
        newkey("ec", &["ec_paramgen_curve:secp256r1"]),
        Err(Error::Unsupported(_))
    ));
    assert!(matches!(
        newkey("rsa:2048", &[]),
        Err(Error::Unsupported(_))
    ));
    assert!(matches!(
        newkey("ed25519:f", &[]),
        Err(Error::Unsupported(_))
    ));
    assert!(matches!(
        newkey("ec", &["rsa_keygen_bits:2048"]),
        Err(Error::Unsupported(_))
    ));
}

/// `-newkey ec:<file>` reads the curve from `openssl ecparam`'s output.
#[test]
fn parameters_file() {
    let dir = std::env::temp_dir()
        .join(format!("baldssl-keygen-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("p.pem");
    // `openssl ecparam -name secp384r1`: the OID 1.3.132.0.34.
    std::fs::write(
        &file,
        "-----BEGIN EC PARAMETERS-----\nBgUrgQQAIg==\n-----END EC PARAMETERS-----\n",
    )
    .unwrap();
    let mut p = KeyParameters::default();
    p.set_newkey("req", OsStr::new(&format!("ec:{}", file.display())))
        .unwrap();
    assert_eq!(p.algorithm("req").unwrap(), Algorithm::P384);
    std::fs::remove_file(&file).unwrap();
    std::fs::remove_dir(&dir).unwrap();
}
