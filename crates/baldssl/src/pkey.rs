//! `baldssl pkey`: read, convert, print and check keys, like `openssl
//! pkey`.
//!
//! Supported: `-in` (standard input without it), `-inform PEM|DER`
//! (detected without it), `-pubin` (the input is a public key), `-out`,
//! `-outform PEM|DER`, `-pubout` (write the public key; implied by
//! `-pubin`), `-noout`, `-text` and `-text_pub` (the key as OpenSSL prints
//! it, by the release line `BALDSSL_OPENSSL_COMPAT` names), `-check` and
//! `-pubcheck`. A private key in DER is written as OpenSSL 3 writes it, in
//! its traditional form when it has one (SEC1 for EC), and as OpenSSL 4
//! does, in PKCS#8. As in OpenSSL, the check's "Key is valid" comes first, then
//! the key, then the text, all on the output; a private key written to a
//! file is created readable by its owner only (`bio_open_owner`).
//!
//! The keys baldssl reads are checked as they are read (a point on its
//! curve, a scalar in range, the public key derived from the secret), so a
//! key that reads is valid. Not supported, and reported as such: encrypted
//! keys (`-passin`, `-passout`, a cipher), `-traditional`, and RSA keys.

use std::{ffi::OsString, io::Write as _, path::Path};

use baldssl_core::{
    Error, Result,
    encoding::{Decodable, Encodable},
    pem::Pem,
};
use baldssl_fs::{create_owner_only, write_error};
use baldssl_pkey::{AnyPrivateKey, PublicKey};
use baldssl_x509::{
    Compat, Format, print_private_key_text, print_public_key_text,
};

use crate::{
    args::{self, Kind, Spec},
    input::{is_pem, parse_format, read_input},
};

/// Every option `baldssl pkey` accepts.
pub(crate) const SPECS: &[Spec] = &[
    Spec {
        name: "help",
        kind: Kind::Flag,
        help: "Display this summary",
    },
    Spec {
        name: "in",
        kind: Kind::Value,
        help: "Key input file (default stdin)",
    },
    Spec {
        name: "inform",
        kind: Kind::Value,
        help: "Input format: PEM or DER (default: detect)",
    },
    Spec {
        name: "pubin",
        kind: Kind::Flag,
        help: "The input is a public key",
    },
    Spec {
        name: "out",
        kind: Kind::Value,
        help: "Output file (default stdout)",
    },
    Spec {
        name: "outform",
        kind: Kind::Value,
        help: "Output format: PEM or DER (default PEM)",
    },
    Spec {
        name: "pubout",
        kind: Kind::Flag,
        help: "Write the public key",
    },
    Spec {
        name: "noout",
        kind: Kind::Flag,
        help: "Do not write the key",
    },
    Spec {
        name: "text",
        kind: Kind::Flag,
        help: "Print the key in text form",
    },
    Spec {
        name: "text_pub",
        kind: Kind::Flag,
        help: "Print the public key in text form",
    },
    Spec {
        name: "check",
        kind: Kind::Flag,
        help: "Check the key",
    },
    Spec {
        name: "pubcheck",
        kind: Kind::Flag,
        help: "Check the public key",
    },
    Spec {
        name: "passin",
        kind: Kind::Value,
        help: "Input pass phrase source (not supported)",
    },
    Spec {
        name: "passout",
        kind: Kind::Value,
        help: "Output pass phrase source (not supported)",
    },
    Spec {
        name: "traditional",
        kind: Kind::Flag,
        help: "Traditional format for private keys (not supported)",
    },
];

/// A key read: private, or public only (`-pubin`).
enum Key {
    /// A private key.
    Private(AnyPrivateKey),
    /// A public key.
    Public(PublicKey),
}

impl Key {
    /// The public key.
    fn public(&self) -> PublicKey {
        match self {
            Key::Private(k) => PublicKey::from(k),
            Key::Public(p) => p.clone(),
        }
    }
}

/// Which key is written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Written {
    /// The key as read.
    #[default]
    AsRead,
    /// Its public key (`-pubout`, or `-pubin`).
    Public,
    /// None (`-noout`).
    Nothing,
}

/// What is printed in text form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Text {
    /// Nothing.
    #[default]
    Nothing,
    /// The key as read (`-text`).
    AsRead,
    /// Its public key (`-text_pub`, or `-text` with `-pubin`).
    Public,
}

/// The options, once read.
#[derive(Debug, Default)]
struct Options {
    input: Option<OsString>,
    inform: Option<Format>,
    public_input: bool,
    output_path: Option<OsString>,
    outform: Option<Format>,
    written: Written,
    text: Text,
    check: bool,
}

fn parse_options(raw: &[OsString]) -> Result<Option<Options>> {
    let opts = args::parse("pkey", raw, SPECS, |_| false)?;
    let mut o = Options::default();
    let mut pubout = false;
    let mut noout = false;
    for opt in opts {
        let value = opt.value.clone().unwrap_or_default();
        match opt.name.as_str() {
            "help" => return Ok(None),
            "in" => o.input = Some(value),
            "inform" => {
                o.inform = Some(parse_format(&value, "pkey", "inform")?);
            }
            "pubin" => o.public_input = true,
            "out" => o.output_path = Some(value),
            "outform" => {
                o.outform = Some(parse_format(&value, "pkey", "outform")?);
            }
            "pubout" => pubout = true,
            "noout" => noout = true,
            "text" if o.text == Text::Nothing => o.text = Text::AsRead,
            "text" => {}
            "text_pub" => o.text = Text::Public,
            "check" | "pubcheck" => o.check = true,
            name => {
                return Err(Error::unsupported(format!("pkey -{name}")));
            }
        }
    }
    // As in OpenSSL's pkey.c: -pubin implies -pubout and public text.
    if o.public_input {
        pubout = true;
        if o.text == Text::AsRead {
            o.text = Text::Public;
        }
    }
    o.written = match (noout, pubout) {
        (true, _) => Written::Nothing,
        (false, true) => Written::Public,
        (false, false) => Written::AsRead,
    };
    Ok(Some(o))
}

/// The key of the input.
fn read_key(o: &Options) -> Result<Key> {
    let bytes = read_input(o.input.as_deref())?;
    let pem = o
        .inform
        .map_or_else(|| is_pem(&bytes), |f| f == Format::Pem);
    Ok(match (o.public_input, pem) {
        (true, true) => Key::Public(PublicKey::from_pem(&bytes)?),
        (true, false) => Key::Public(PublicKey::decode(&bytes)?),
        (false, true) => Key::Private(AnyPrivateKey::from_pem(&bytes)?),
        (false, false) => Key::Private(AnyPrivateKey::decode(&bytes)?),
    })
}

/// Renders what `pkey` writes, and where.
///
/// # Errors
///
/// Usage errors, unreadable keys, and unsupported options or keys.
pub(crate) fn render(raw: &[OsString]) -> Result<(Vec<u8>, Option<OsString>)> {
    let Some(o) = parse_options(raw)? else {
        return Ok((args::usage("pkey", SPECS).into_bytes(), None));
    };
    let compat = crate::x509::compat()?;
    let key = read_key(&o)?;
    let mut out = Vec::new();
    if o.check {
        out.extend_from_slice(b"Key is valid\n");
    }
    let der = o.outform == Some(Format::Der);
    let writes_private = match (o.written, &key) {
        (Written::Nothing, _) => false,
        (Written::AsRead, Key::Private(k)) => {
            // OpenSSL 3 writes a private key in DER in its algorithm's
            // traditional form when it has one (SEC1 for EC); OpenSSL 4
            // writes PKCS#8, as for PEM.
            if der && compat != Compat::V4 {
                out.extend_from_slice(
                    &k.traditional_opt().unwrap_or_else(|| k.encode()),
                );
            } else if der {
                out.extend_from_slice(&k.encode());
            } else {
                out.extend_from_slice(k.to_pem().as_bytes());
            }
            true
        }
        (Written::AsRead | Written::Public, _) => {
            let public = key.public();
            if der {
                out.extend_from_slice(&public.encode());
            } else {
                out.extend_from_slice(public.to_pem().as_bytes());
            }
            false
        }
    };
    match (o.text, &key) {
        (Text::Nothing, _) => {}
        (Text::AsRead, Key::Private(k)) => {
            out.extend_from_slice(&print_private_key_text(k, compat)?);
        }
        (Text::AsRead | Text::Public, _) => {
            out.extend_from_slice(&print_public_key_text(
                &key.public(),
                compat,
            )?);
        }
    }
    // A private key goes to a file only its owner can read, as OpenSSL's
    // bio_open_owner creates it.
    match (&o.output_path, writes_private) {
        (Some(path), true) => {
            let path = Path::new(path);
            create_owner_only(path)?
                .write_all(&out)
                .map_err(|e| write_error(path, &e))?;
            Ok((Vec::new(), None))
        }
        _ => Ok((out, o.output_path)),
    }
}

#[cfg(test)]
mod tests;
