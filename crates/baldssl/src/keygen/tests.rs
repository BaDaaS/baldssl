//! Curve names, `-newkey` values and the key file's mode.

use std::ffi::OsStr;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;

use baldssl_core::Error;
use baldssl_pkey::Algorithm;

use super::{KeyParameters, curve_opt, write_private_key};

#[test]
fn curve_names() {
    assert_eq!(curve_opt("P-256"), Some(Algorithm::P256));
    assert_eq!(curve_opt("prime256v1"), Some(Algorithm::P256));
    assert_eq!(curve_opt("secp384r1"), Some(Algorithm::P384));
    assert_eq!(curve_opt("p-521"), Some(Algorithm::P521));
    assert_eq!(curve_opt("secp256r1"), None);
}

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
    assert!(matches!(newkey("ec", &[]), Err(Error::Usage(_))));
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

/// A new key file holds the key, and on Unix is readable and writable by
/// its owner only.
#[test]
fn key_file_mode() {
    let dir = std::env::temp_dir()
        .join(format!("baldssl-keyfile-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("k.pem");
    write_private_key(&file, b"secret").unwrap();
    #[cfg(unix)]
    {
        let mode = std::fs::metadata(&file).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    assert_eq!(std::fs::read(&file).unwrap(), b"secret");
    std::fs::remove_file(&file).unwrap();
    std::fs::remove_dir(&dir).unwrap();
}
