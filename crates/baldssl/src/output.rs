//! Where a command's output goes: a file, or standard output.

use std::{
    ffi::OsString,
    fs,
    io::{self, Write as _},
};

use baldssl_core::Error;

/// Writes `bytes` to `path`, or to standard output without one.
///
/// # Errors
///
/// [`Error::Io`] when the file or standard output cannot be written.
pub(crate) fn write_output(
    bytes: &[u8],
    path: Option<&OsString>,
) -> Result<(), Error> {
    let io_err = |context: String| {
        move |e: io::Error| Error::Io {
            context,
            message: e.to_string(),
        }
    };
    if let Some(p) = path {
        fs::write(p, bytes)
            .map_err(io_err(format!("writing {}", p.to_string_lossy())))
    } else {
        let mut stdout = io::stdout().lock();
        stdout
            .write_all(bytes)
            .and_then(|()| stdout.flush())
            .map_err(io_err("writing stdout".into()))
    }
}
