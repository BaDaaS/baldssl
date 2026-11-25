//! The filesystem side of baldssl: reading input files and standard input,
//! opening output files with the access OpenSSL gives them, writing the
//! standard streams, and writing encodings and text forms to any writer.
//!
//! Encodings ([`Pem`], PEM being Privacy-Enhanced Mail, [RFC 7468]) and
//! text forms ([`Text`]) live with their types and do no I/O, which keeps
//! `baldssl-core` extractable to Lean. This crate is the edge where they
//! meet the operating system.
//!
//! [RFC 7468]: https://www.rfc-editor.org/rfc/rfc7468

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt as _;
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read as _, Write as _},
    path::Path,
};

use baldssl_core::{Error, Result, pem::Pem, text::Text};

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

/// Writing the text form of a value to any [`io::Write`]. Every [`Text`]
/// type has it.
pub trait WriteText: Text {
    /// Writes the text form of `self` under `layout` ([`Text::to_text`]) to
    /// `out`, then flushes it.
    ///
    /// # Errors
    ///
    /// The errors of [`Text::to_text`], and [`Error::Io`] for the writer's.
    fn write_text<W>(&self, layout: Self::Layout, mut out: W) -> Result<()>
    where
        W: io::Write,
    {
        let text = self.to_text(layout)?;
        out.write_all(&text)
            .and_then(|()| out.flush())
            .map_err(|e| Error::Io {
                context: "writing text".into(),
                message: e.to_string(),
            })
    }
}

impl<T> WriteText for T where T: Text {}

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

/// Who may read a file baldssl writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// What the process's umask allows, as OpenSSL's `bio_open_default`
    /// creates a file.
    Default,
    /// Its owner only ([`create_owner_only`]), as OpenSSL's
    /// `bio_open_owner` creates a file that holds a private key.
    OwnerOnly,
}

/// Writes `bytes` to `path`, created (or truncated) with `access`.
///
/// # Errors
///
/// [`Error::Io`] when the file cannot be created or written.
pub fn write_file(path: &Path, access: Access, bytes: &[u8]) -> Result<()> {
    match access {
        Access::Default => fs::write(path, bytes),
        Access::OwnerOnly => create_owner_only(path)?.write_all(bytes),
    }
    .map_err(|e| write_error(path, &e))
}

/// Writes `bytes` on standard output, then flushes it.
///
/// # Errors
///
/// [`Error::Io`] when standard output cannot be written.
pub fn write_stdout(bytes: &[u8]) -> Result<()> {
    let mut stdout = io::stdout().lock();
    stdout
        .write_all(bytes)
        .and_then(|()| stdout.flush())
        .map_err(|e| Error::Io {
            context: "writing stdout".into(),
            message: e.to_string(),
        })
}

/// Writes `bytes` on standard error, then flushes it.
///
/// # Errors
///
/// [`Error::Io`] when standard error cannot be written.
pub fn write_stderr(bytes: &[u8]) -> Result<()> {
    let mut stderr = io::stderr().lock();
    stderr
        .write_all(bytes)
        .and_then(|()| stderr.flush())
        .map_err(|e| Error::Io {
            context: "writing stderr".into(),
            message: e.to_string(),
        })
}

/// The bytes of `path`, or of standard input without one.
///
/// # Errors
///
/// [`Error::NotFound`] for a missing file, [`Error::Io`] otherwise.
pub fn read_input(path: Option<&Path>) -> Result<Vec<u8>> {
    match path {
        None => {
            let mut buf = Vec::new();
            io::stdin().read_to_end(&mut buf).map_err(|e| Error::Io {
                context: "reading stdin".into(),
                message: e.to_string(),
            })?;
            Ok(buf)
        }
        Some(p) => fs::read(p).map_err(|e| {
            let shown = p.display().to_string();
            if e.kind() == io::ErrorKind::NotFound {
                Error::NotFound { path: shown }
            } else {
                Error::Io {
                    context: format!("reading {shown}"),
                    message: e.to_string(),
                }
            }
        }),
    }
}

/// The bytes of `path`, or `None` when it does not exist (a serial file
/// `-CAcreateserial` creates).
///
/// # Errors
///
/// [`Error::Io`] when it exists and cannot be read.
pub fn read_if_present(path: &Path) -> Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(Error::Io {
            context: format!("reading {}", path.display()),
            message: e.to_string(),
        }),
    }
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
