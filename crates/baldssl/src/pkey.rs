//! `baldssl pkey`: read, convert, print and check keys, like `openssl
//! pkey`.
//!
//! Supported: `-in` (standard input without it), `-inform PEM|DER`
//! (detected without it), `-pubin` (the input is a public key), `-out`,
//! `-outform PEM|DER`, `-pubout` (write the public key; implied by
//! `-pubin`), `-noout`, `-text` and `-text_pub` (the key as OpenSSL prints
//! it, by the release line baldssl is built for), `-check` and
//! `-pubcheck`. A private key in DER is written as OpenSSL 3.0 to 3.5 write
//! it, in its traditional form when it has one (SEC 1's ECPrivateKey for
//! EC), and as 3.6 and 4 do, in PKCS#8, by the release line
//! ([`Apps::PRIVATE_KEY_DER`](crate::line::Apps::PRIVATE_KEY_DER)). As in OpenSSL, the check's
//! "Key is valid" comes first, then the key, then the text, all on the
//! output; a private key written to a file is created readable by its
//! owner only (`bio_open_owner`).
//!
//! The keys baldssl reads are checked as they are read (a point on its
//! curve, a scalar in range, the public key derived from the secret), so a
//! key that reads is valid. Not supported, and reported as such: encrypted
//! keys (`-passin`, `-passout`, a cipher), `-traditional`, and RSA keys.

use std::ffi::OsString;

use baldssl_core::{
    Error, Result,
    encoding::{Decodable, Encodable},
    pem::Pem,
};
use baldssl_fs::Access;
use baldssl_pkey::{AnyPrivateKey, PublicKey};
use baldssl_x509::{
    Format, TextLayout, print_private_key_text, print_public_key_text,
};

use crate::{
    args::{self, Kind, Spec, Unknown},
    input::{format_value, read_input},
    line::{Apps as _, Line},
    outputs::Outputs,
};

/// The name of the command.
const COMMAND: &str = "pkey";

/// What `-check` and `-pubcheck` print before the key (`apps/pkey.c`).
const KEY_IS_VALID: &[u8] = b"Key is valid\n";

/// An option of `baldssl pkey`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Opt {
    /// `-help`.
    Help,
    /// `-in`.
    In(OsString),
    /// `-inform`.
    Inform(OsString),
    /// `-pubin`.
    Pubin,
    /// `-out`.
    Out(OsString),
    /// `-outform`.
    Outform(OsString),
    /// `-pubout`.
    Pubout,
    /// `-noout`.
    Noout,
    /// `-text`.
    Text,
    /// `-text_pub`.
    TextPub,
    /// `-check`.
    Check,
    /// `-pubcheck`.
    Pubcheck,
    /// `-passin`.
    Passin(OsString),
    /// `-passout`.
    Passout(OsString),
    /// `-traditional`.
    Traditional,
}

/// Every option `baldssl pkey` accepts.
pub(crate) const SPECS: &[Spec<Opt>] = &[
    Spec {
        name: "help",
        kind: Kind::Flag(Opt::Help),
        help: "Display this summary",
    },
    Spec {
        name: "in",
        kind: Kind::Value(Opt::In),
        help: "Key input file (default stdin)",
    },
    Spec {
        name: "inform",
        kind: Kind::Value(Opt::Inform),
        help: "Input format: PEM or DER (default: detect)",
    },
    Spec {
        name: "pubin",
        kind: Kind::Flag(Opt::Pubin),
        help: "The input is a public key",
    },
    Spec {
        name: "out",
        kind: Kind::Value(Opt::Out),
        help: "Output file (default stdout)",
    },
    Spec {
        name: "outform",
        kind: Kind::Value(Opt::Outform),
        help: "Output format: PEM or DER (default PEM)",
    },
    Spec {
        name: "pubout",
        kind: Kind::Flag(Opt::Pubout),
        help: "Write the public key",
    },
    Spec {
        name: "noout",
        kind: Kind::Flag(Opt::Noout),
        help: "Do not write the key",
    },
    Spec {
        name: "text",
        kind: Kind::Flag(Opt::Text),
        help: "Print the key in text form",
    },
    Spec {
        name: "text_pub",
        kind: Kind::Flag(Opt::TextPub),
        help: "Print the public key in text form",
    },
    Spec {
        name: "check",
        kind: Kind::Flag(Opt::Check),
        help: "Check the key",
    },
    Spec {
        name: "pubcheck",
        kind: Kind::Flag(Opt::Pubcheck),
        help: "Check the public key",
    },
    Spec {
        name: "passin",
        kind: Kind::Value(Opt::Passin),
        help: "Input pass phrase source (not supported)",
    },
    Spec {
        name: "passout",
        kind: Kind::Value(Opt::Passout),
        help: "Output pass phrase source (not supported)",
    },
    Spec {
        name: "traditional",
        kind: Kind::Flag(Opt::Traditional),
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

/// What the input holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum KeyInput {
    /// A private key.
    #[default]
    Private,
    /// A public key (`-pubin`).
    Public,
}

/// Which key is written. The options only move it up this order (no later
/// option undoes `-pubout` or `-noout`, as in `apps/pkey.c`), so it is the
/// maximum of what they ask for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
enum Written {
    /// The key as read.
    #[default]
    AsRead,
    /// Its public key (`-pubout`, or `-pubin`).
    Public,
    /// None (`-noout`).
    Nothing,
}

/// What is printed in text form. As for [`Written`], the options only move
/// it up: `-text_pub` wins over `-text`, in either order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
enum Text {
    /// Nothing.
    #[default]
    Nothing,
    /// The key as read (`-text`).
    AsRead,
    /// Its public key (`-text_pub`, or `-text` with `-pubin`).
    Public,
}

/// Whether the key is checked (`-check`, `-pubcheck`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Check {
    /// It is not.
    #[default]
    Skipped,
    /// "Key is valid" comes first.
    Reported,
}

/// The options, once read.
#[derive(Debug, Default)]
struct Options {
    input: Option<OsString>,
    inform: Option<Format>,
    key_input: KeyInput,
    output_path: Option<OsString>,
    outform: Option<Format>,
    written: Written,
    text: Text,
    check: Check,
}

/// The options, or `None` for `-help`.
fn parse_options(raw: &[OsString]) -> Result<Option<Options>> {
    let opts = args::parse(COMMAND, raw, SPECS, Unknown::Ciphers)?;
    let mut o = Options::default();
    for given in opts {
        match given.option {
            Opt::Help => return Ok(None),
            Opt::In(v) => o.input = Some(v),
            Opt::Inform(v) => {
                o.inform = Some(format_value(&v, COMMAND, "inform")?);
            }
            Opt::Pubin => o.key_input = KeyInput::Public,
            Opt::Out(v) => o.output_path = Some(v),
            Opt::Outform(v) => {
                o.outform = Some(format_value(&v, COMMAND, "outform")?);
            }
            Opt::Pubout => o.written = o.written.max(Written::Public),
            Opt::Noout => o.written = o.written.max(Written::Nothing),
            Opt::Text => o.text = o.text.max(Text::AsRead),
            Opt::TextPub => o.text = o.text.max(Text::Public),
            Opt::Check | Opt::Pubcheck => o.check = Check::Reported,
            Opt::Passin(_) | Opt::Passout(_) | Opt::Traditional => {
                return Err(Error::unsupported(format!(
                    "{COMMAND} -{}",
                    given.name
                )));
            }
        }
    }
    // As in OpenSSL's pkey.c: -pubin implies -pubout and public text.
    match o.key_input {
        KeyInput::Private => {}
        KeyInput::Public => {
            o.written = o.written.max(Written::Public);
            o.text = match o.text {
                Text::Nothing => Text::Nothing,
                Text::AsRead | Text::Public => Text::Public,
            };
        }
    }
    Ok(Some(o))
}

/// The key of the input.
fn read_key(o: &Options) -> Result<Key> {
    let bytes = read_input(o.input.as_deref())?;
    Ok(
        match (o.key_input, Format::given_or_detected(o.inform, &bytes)) {
            (KeyInput::Public, Format::Pem) => {
                Key::Public(PublicKey::from_pem(&bytes)?)
            }
            (KeyInput::Public, Format::Der) => {
                Key::Public(PublicKey::decode(&bytes)?)
            }
            (KeyInput::Private, Format::Pem) => {
                Key::Private(AnyPrivateKey::from_pem(&bytes)?)
            }
            (KeyInput::Private, Format::Der) => {
                Key::Private(AnyPrivateKey::decode(&bytes)?)
            }
        },
    )
}

/// Reads the key, and records what `pkey` writes.
///
/// # Errors
///
/// Usage errors, unreadable keys, and unsupported options or keys.
pub(crate) fn run(raw: &[OsString], outputs: &mut Outputs) -> Result<()> {
    let Some(o) = parse_options(raw)? else {
        outputs.stdout(args::usage(COMMAND, SPECS));
        return Ok(());
    };
    let key = read_key(&o)?;
    let mut out = Vec::new();
    match o.check {
        Check::Skipped => {}
        Check::Reported => out.extend_from_slice(KEY_IS_VALID),
    }
    // PEM without -outform, as `apps/pkey.c` starts from FORMAT_PEM.
    let outform = o.outform.unwrap_or(Format::Pem);
    // A private key goes to a file only its owner can read, as OpenSSL's
    // bio_open_owner creates it.
    let access = match (o.written, &key, outform) {
        (Written::Nothing, _, _) => Access::Default,
        (Written::AsRead, Key::Private(k), Format::Pem) => {
            out.extend_from_slice(k.to_pem().as_bytes());
            Access::OwnerOnly
        }
        (Written::AsRead, Key::Private(k), Format::Der) => {
            out.extend_from_slice(k.der(Line::PRIVATE_KEY_DER).expose());
            Access::OwnerOnly
        }
        (Written::AsRead | Written::Public, _, Format::Pem) => {
            out.extend_from_slice(key.public().to_pem().as_bytes());
            Access::Default
        }
        (Written::AsRead | Written::Public, _, Format::Der) => {
            out.extend_from_slice(&key.public().encode());
            Access::Default
        }
    };
    match (o.text, &key) {
        (Text::Nothing, _) => {}
        (Text::AsRead, Key::Private(k)) => {
            out.extend_from_slice(&print_private_key_text(
                k,
                TextLayout::of::<Line>(),
            )?);
        }
        (Text::AsRead | Text::Public, _) => {
            out.extend_from_slice(&print_public_key_text(
                &key.public(),
                TextLayout::of::<Line>(),
            )?);
        }
    }
    outputs.output(o.output_path.as_deref(), access, out);
    Ok(())
}

#[cfg(test)]
mod tests;
