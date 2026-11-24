//! The PEM writer and the owner-only file.

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;

use baldssl_core::{Result, encoding::Encodable, pem::Pem, text::Text};

use super::{WritePem as _, WriteText as _, create_owner_only};

/// A value whose encoding is fixed bytes.
struct Fixed(&'static [u8]);

impl Encodable for Fixed {
    type Bytes = &'static [u8];

    fn encode(&self) -> &'static [u8] {
        self.0
    }
}

impl Pem for Fixed {
    const LABEL: &'static str = "TEST";
}

impl Text for Fixed {
    type Layout = u8;

    /// The encoding, followed by the layout.
    fn to_text(&self, layout: u8) -> Result<Vec<u8>> {
        let mut out = self.0.to_vec();
        out.push(layout);
        Ok(out)
    }
}

/// `write_text` writes exactly `to_text`, under the layout given.
#[test]
fn write_text_is_to_text() {
    let value = Fixed(b"baldssl");
    let mut out = Vec::new();
    value.write_text(b'!', &mut out).unwrap();
    assert_eq!(out, value.to_text(b'!').unwrap());
    assert_eq!(out, b"baldssl!");
}

/// `write_pem` writes exactly `to_pem`.
#[test]
fn write_pem_is_to_pem() {
    let value = Fixed(b"baldssl");
    let mut out = Vec::new();
    value.write_pem(&mut out).unwrap();
    assert_eq!(out, value.to_pem().into_bytes());
}

/// A new owner-only file holds what was written, and on Unix is readable
/// and writable by its owner only.
#[test]
fn owner_only_file() {
    let dir =
        std::env::temp_dir().join(format!("baldssl-fs-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("k.pem");
    let value = Fixed(b"secret");
    value.write_pem(create_owner_only(&file).unwrap()).unwrap();
    #[cfg(unix)]
    {
        let mode = std::fs::metadata(&file).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    assert_eq!(std::fs::read_to_string(&file).unwrap(), value.to_pem());
    std::fs::remove_file(&file).unwrap();
    std::fs::remove_dir(&dir).unwrap();
}
