//! The options of `req`: what each sets, and what is refused.

use std::ffi::OsString;

use baldssl_core::Error;
use baldssl_crypto::Algorithm as Digest;
use baldssl_x509::InputEncoding;

use baldssl_core::der::TimeKind;

use baldssl_fs::Access;
use baldssl_pkey::AnyPrivateKey;
use baldssl_x509::{
    CertificationRequest, Compat, DistinguishedName, Extensions,
};

use super::{KeySource, Mode, Product, Verify, parse_options, run, verify};
use crate::{
    input::OutputForm,
    issuing::{SerialSource, ValidityTime},
    outputs::{Effect, Outputs},
};

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
    assert_eq!(o.output, OutputForm::Pem);
    assert_eq!(o.encoding, InputEncoding::Latin1);
    assert_eq!(o.verify, Verify::Skipped);
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
    assert_eq!(options(&["-outform", "DER"]).output, OutputForm::Der);
    assert_eq!(
        options(&["-noout", "-outform", "DER"]).output,
        OutputForm::Nothing
    );
    assert_eq!(
        options(&["-outform", "DER", "-noout"]).output,
        OutputForm::Nothing
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
        parse_options(&os(&["-config", "c.cnf"])).err(),
        Some(Error::unsupported("req -config"))
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
        parse_options(&os(&["-newkey", "ed25519"])).err(),
        Some(Error::unsupported(
            "req -newkey without -noenc (encrypting the key)"
        ))
    );
    assert!(matches!(
        parse_options(&os(&["-key", "k.pem", "-newkey", "ed25519", "-noenc"])),
        Err(Error::Usage(_))
    ));
    assert_eq!(
        parse_options(&os(&["-sha1"])).err(),
        Some(Error::unsupported("digest sha1"))
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
    let Some(ValidityTime::At(before)) = o.lifetime.not_before else {
        panic!("a time")
    };
    assert_eq!((before.kind(), before.year()), (TimeKind::Utc, 2026));
    let Some(ValidityTime::At(after)) = o.lifetime.not_after else {
        panic!("a time")
    };
    assert_eq!((after.kind(), after.year()), (TimeKind::Generalized, 2050));
    // A GeneralizedTime before 2050 is written as a UTCTime.
    let o = options(&["-x509", "-not_before", "20261122000000Z"]);
    assert!(matches!(
        o.lifetime.not_before,
        Some(ValidityTime::At(t)) if t.kind() == TimeKind::Utc
    ));
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

/// `-newkey` implies `-new`, with `privkey.pem` as the key file unless
/// `-keyout` names another; `-pkeyopt` may come before it.
#[test]
fn new_keys() {
    let o = options(&[
        "-pkeyopt",
        "ec_paramgen_curve:P-256",
        "-newkey",
        "ec",
        "-nodes",
    ]);
    assert_eq!(o.mode, Mode::Create);
    let Some(KeySource::New(new)) = o.key else {
        panic!("a new key")
    };
    assert_eq!(new.keyout, OsString::from("privkey.pem"));
    assert_eq!(
        new.parameters.algorithm().unwrap(),
        baldssl_pkey::Algorithm::P256
    );
    let o =
        options(&["-x509", "-newkey", "ed25519", "-noenc", "-keyout", "k.pem"]);
    assert_eq!((o.mode, o.product), (Mode::Create, Product::Certificate));
    assert!(matches!(o.key, Some(KeySource::New(n)) if n.keyout == "k.pem"));
    assert!(matches!(
        options(&["-key", "k.pem"]).key,
        Some(KeySource::File(f)) if f == "k.pem"
    ));
}

/// `-addext`: one extension per name, as OpenSSL counts names.
#[test]
fn added_extensions() {
    let o = options(&[
        "-addext",
        "subjectAltName=DNS:a.example",
        "-addext",
        "keyUsage=critical,digitalSignature",
    ]);
    assert_eq!(o.extensions.as_slice().len(), 2);
    assert!(o.extensions.as_slice()[1].critical);
    assert_eq!(
        parse_options(&os(&[
            "-addext",
            "keyUsage=digitalSignature",
            "-addext",
            "keyUsage=cRLSign"
        ]))
        .err(),
        Some(Error::Usage("Duplicate extension name: keyUsage".into()))
    );
    assert!(matches!(
        parse_options(&os(&["-addext", "fooBar=x"])),
        Err(Error::Usage(_))
    ));
}

fn run_to_outputs(v: &[&str]) -> (Outputs, baldssl_core::Result<()>) {
    let mut out = Outputs::default();
    let result = run(&os(v), &mut out);
    (out, result)
}

/// `-newkey`: OpenSSL's line on standard error and the key in a file only
/// its owner reads, then the warning for a skipped `-subj` attribute, then
/// the request.
#[test]
fn new_key_effects() {
    let (out, result) = run_to_outputs(&[
        "-newkey",
        "ed25519",
        "-noenc",
        "-keyout",
        "k.pem",
        "-subj",
        "/CN=x/bogus=1",
    ]);
    result.unwrap();
    let [
        Effect::Stderr(line),
        Effect::File {
            path,
            access: Access::OwnerOnly,
            bytes: key,
        },
        Effect::Stderr(warning),
        Effect::Stdout(request),
    ] = out.effects()
    else {
        panic!("{:?}", out.effects())
    };
    assert_eq!(line, b"-----\n");
    assert_eq!(
        warning,
        b"req warning: Skipping unknown subject name attribute \"bogus\"\n"
    );
    assert_eq!(path, std::path::Path::new("k.pem"));
    assert!(key.starts_with(b"-----BEGIN PRIVATE KEY-----\n"));
    assert!(request.starts_with(b"-----BEGIN CERTIFICATE REQUEST-----\n"));
    // The key is written before the subject is read: a bad subject fails
    // after the key file, as in OpenSSL.
    let (out, result) =
        run_to_outputs(&["-newkey", "ed25519", "-nodes", "-subj", "CN=x"]);
    assert!(result.is_err());
    assert!(matches!(
        out.effects(),
        [Effect::Stderr(_), Effect::File { .. }]
    ));
}

/// `-verify`'s success goes to standard error in OpenSSL 3.0 and to
/// standard output from 3.2.
#[test]
fn verified_stream() {
    let key =
        AnyPrivateKey::generate(baldssl_pkey::Algorithm::Ed25519).unwrap();
    let request = CertificationRequest::sign(
        &DistinguishedName::default(),
        &key,
        key.default_signature_algorithm(),
        &Extensions::new(),
    )
    .unwrap();
    for (compat, stdout, stderr) in [
        (
            Compat::V30,
            &b""[..],
            &b"Certificate request self-signature verify OK\n"[..],
        ),
        (
            Compat::V3,
            b"Certificate request self-signature verify OK\n",
            b"",
        ),
        (
            Compat::V36,
            b"Certificate request self-signature verify OK\n",
            b"",
        ),
        (
            Compat::V4,
            b"Certificate request self-signature verify OK\n",
            b"",
        ),
    ] {
        if compat != crate::line::compat() {
            continue;
        }
        let mut out = Outputs::default();
        verify(&request, &mut out).unwrap();
        assert_eq!(out.stdout_bytes(), stdout, "{compat:?}");
        assert_eq!(out.stderr_bytes(), stderr, "{compat:?}");
    }
}
