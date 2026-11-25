//! What a command produces, in the order it produces it: bytes for
//! standard output, messages for standard error, and files. A command
//! records them here and does no output itself; `main` hands them to
//! `baldssl-fs`, so a command is tested by what it records.

use std::{
    ffi::OsStr,
    path::{Path, PathBuf},
};

use baldssl_core::Result;
use baldssl_fs::{Access, write_file, write_stderr, write_stdout};

/// One thing a command writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Effect {
    /// Bytes for standard output.
    Stdout(Vec<u8>),
    /// Bytes for standard error.
    Stderr(Vec<u8>),
    /// A file, created or truncated.
    File {
        /// Where.
        path: PathBuf,
        /// Who may read it.
        access: Access,
        /// Its contents.
        bytes: Vec<u8>,
    },
}

/// Everything a command writes, in order.
#[derive(Debug, Default)]
pub(crate) struct Outputs {
    /// The effects, in the order the command produced them.
    effects: Vec<Effect>,
}

impl Outputs {
    /// Bytes for standard output.
    pub(crate) fn stdout(&mut self, bytes: impl Into<Vec<u8>>) {
        self.effects.push(Effect::Stdout(bytes.into()));
    }

    /// Bytes for standard error.
    pub(crate) fn stderr(&mut self, bytes: impl Into<Vec<u8>>) {
        self.effects.push(Effect::Stderr(bytes.into()));
    }

    /// One line for standard error: `line` and a newline.
    pub(crate) fn diagnostic(&mut self, line: impl AsRef<[u8]>) {
        let mut bytes = line.as_ref().to_vec();
        bytes.push(b'\n');
        self.stderr(bytes);
    }

    /// A file written with `access`.
    pub(crate) fn file(
        &mut self,
        path: impl AsRef<Path>,
        access: Access,
        bytes: impl Into<Vec<u8>>,
    ) {
        self.effects.push(Effect::File {
            path: path.as_ref().to_path_buf(),
            access,
            bytes: bytes.into(),
        });
    }

    /// A command's main output: to the file `-out` names, created with
    /// `access`, or to standard output without one.
    pub(crate) fn output(
        &mut self,
        path: Option<&OsStr>,
        access: Access,
        bytes: impl Into<Vec<u8>>,
    ) {
        match path {
            Some(p) => self.file(p, access, bytes),
            None => self.stdout(bytes),
        }
    }

    /// The effects, in order.
    #[cfg(test)]
    pub(crate) fn effects(&self) -> &[Effect] {
        &self.effects
    }

    /// Everything for standard output, concatenated.
    #[cfg(test)]
    pub(crate) fn stdout_bytes(&self) -> Vec<u8> {
        self.effects
            .iter()
            .filter_map(|e| match e {
                Effect::Stdout(b) => Some(b.as_slice()),
                Effect::Stderr(_) | Effect::File { .. } => None,
            })
            .flatten()
            .copied()
            .collect()
    }

    /// Everything for standard error, concatenated.
    #[cfg(test)]
    pub(crate) fn stderr_bytes(&self) -> Vec<u8> {
        self.effects
            .iter()
            .filter_map(|e| match e {
                Effect::Stderr(b) => Some(b.as_slice()),
                Effect::Stdout(_) | Effect::File { .. } => None,
            })
            .flatten()
            .copied()
            .collect()
    }

    /// Carries the effects out: standard error and the files in order, as
    /// they come, and standard output, which OpenSSL buffers when it is
    /// not a terminal, at the end. `extra` is what goes to standard output
    /// after the rest (the output of [`baldssl_core::Error::Reported`]).
    ///
    /// # Errors
    ///
    /// The first effect that fails; the ones before it are done.
    pub(crate) fn apply(self, extra: &[u8]) -> Result<()> {
        let mut stdout = Vec::new();
        for effect in self.effects {
            match effect {
                Effect::Stdout(bytes) => stdout.extend(bytes),
                Effect::Stderr(bytes) => write_stderr(&bytes)?,
                Effect::File {
                    path,
                    access,
                    bytes,
                } => write_file(&path, access, &bytes)?,
            }
        }
        stdout.extend_from_slice(extra);
        if stdout.is_empty() {
            return Ok(());
        }
        write_stdout(&stdout)
    }
}
