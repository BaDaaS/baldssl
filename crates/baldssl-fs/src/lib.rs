//! The filesystem side of baldssl: opening output files with the access
//! OpenSSL gives them, and writing encodings to any writer.
//!
//! Encodings themselves ([`Pem`], PEM being Privacy-Enhanced Mail,
//! [RFC 7468]) live in `baldssl-core` and do no I/O, which keeps that crate
//! extractable to Lean. This crate is the edge where they meet the operating
//! system.
//!
//! [RFC 7468]: https://www.rfc-editor.org/rfc/rfc7468

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt as _;
use std::{
    fs::{File, OpenOptions},
    io,
    path::Path,
};

use baldssl_core::{Error, Result, pem::Pem};

/// Writing the PEM armour of a value to any [`io::Write`]: a file, standard
/// output, a buffer. Every [`Pem`] type has it.
pub trait WritePem: Pem {
    /// Writes the PEM armour of `self` ([`Pem::to_pem`]) to `out`, then
    /// flushes it.
    ///
    /// # Errors
    ///
    /// The writer's.
    fn write_pem<W>(&self, mut out: W) -> io::Result<()>
    where
        W: io::Write,
    {
        out.write_all(self.to_pem().as_bytes())?;
        out.flush()
    }
}

impl<T> WritePem for T where T: Pem {}

/// `path`, created (or truncated) for writing, readable and writable by its
/// owner only (mode 0600 where files have modes), as OpenSSL opens key
/// outputs (`bio_open_owner` in `apps/lib/apps.c`). An existing file keeps
/// its mode, as with OpenSSL.
///
/// # Errors
///
/// [`Error::Io`] when the file cannot be created.
pub fn create_owner_only(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    options.mode(0o600);
    options.open(path).map_err(|e| write_error(path, &e))
}

/// The error of writing `path`, as baldssl reports it.
#[must_use]
pub fn write_error(path: &Path, e: &io::Error) -> Error {
    Error::Io {
        context: format!("writing {}", path.display()),
        message: e.to_string(),
    }
}

#[cfg(test)]
mod tests;
