//! Randomness from the operating system.
//!
//! This is the only module of baldssl allowed to use `unsafe`: stable Rust's
//! standard library exposes no source of cryptographic randomness, so the
//! operating system is called directly. `make check-unsafe` (in CI) fails if
//! `unsafe` code appears in any other file. Every call below is the system's
//! documented interface for cryptographic randomness:
//!
//! | Platform                            | Call                                                     | Minimum                  |
//! | ----------------------------------- | -------------------------------------------------------- | ------------------------ |
//! | Linux, glibc                        | `getrandom(2)`, flags 0: blocks until the pool is seeded | glibc 2.25               |
//! | Linux, musl                         | `getrandom(2)`                                           | musl 1.1.20              |
//! | Android (bionic libc)               | `getrandom(2)`                                           | API level 28 (Android 9) |
//! | macOS, iOS                          | `getentropy(2)`, at most 256 bytes per call              | macOS 10.12, iOS 10      |
//! | FreeBSD, OpenBSD, NetBSD, DragonFly | `getentropy(2)`                                          |                          |
//! | Windows                             | `BCryptGenRandom` with `BCRYPT_USE_SYSTEM_PREFERRED_RNG` |                          |
//! | WASI preview 1                      | `random_get` from `wasi_snapshot_preview1`               |                          |
//!
//! Sources of the minimums: the [glibc 2.25 NEWS] ("The getentropy and
//! getrandom functions ... have been added"), the [musl 1.1.20 release
//! notes], the [`sys/random.h`] of bionic, Android's libc
//! (`__INTRODUCED_IN(28)`), and the [`sys/random.h`][xnu] of xnu, the macOS
//! kernel (`__OSX_AVAILABLE(10.12)`).
//!
//! CI checks them: the `os-rng-*` jobs run these tests on every platform and
//! version listed in `website/src/platforms.json` (the website's Platforms
//! table), and a version below a minimum must fail to link.
//!
//! [glibc 2.25 NEWS]: https://sourceware.org/git/?p=glibc.git;a=blob_plain;f=NEWS;hb=HEAD
//! [musl 1.1.20 release notes]: https://git.musl-libc.org/cgit/musl/plain/WHATSNEW
//! [`sys/random.h`]: https://android.googlesource.com/platform/bionic/+/refs/heads/main/libc/include/sys/random.h
//! [xnu]: https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/random.h
//!
//! Any other target, including `wasm32-unknown-unknown` (browsers, which
//! would need JavaScript's `crypto.getRandomValues`), returns
//! [`RngError::Unsupported`].
#![allow(unsafe_code)]
#![deny(clippy::undocumented_unsafe_blocks, unsafe_op_in_unsafe_fn)]

/// Why the operating system could not provide randomness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RngError {
    /// No source of randomness on this target.
    Unsupported,
    /// The system call failed with this error code.
    Os(i32),
    /// The system call returned what its interface rules out: a failure
    /// without an error code, or more bytes than were asked for.
    Unexpected,
}

impl core::fmt::Display for RngError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RngError::Unsupported => {
                f.write_str("no source of randomness on this platform")
            }
            RngError::Os(code) => {
                write!(
                    f,
                    "the operating system's random source failed ({code})"
                )
            }
            RngError::Unexpected => f.write_str(
                "the operating system's random source returned an \
                 unexpected result",
            ),
        }
    }
}

impl std::error::Error for RngError {}

/// What a caller drawing randomness reports: no source on this target is
/// [`Unsupported`](baldssl_core::Error::Unsupported), a failing source an
/// [`Io`](baldssl_core::Error::Io) error with this error's message.
impl From<RngError> for baldssl_core::Error {
    fn from(e: RngError) -> Self {
        match e {
            RngError::Unsupported => baldssl_core::Error::unsupported(
                "key generation: no source of randomness",
            ),
            RngError::Os(_) | RngError::Unexpected => baldssl_core::Error::Io {
                context: "reading randomness".into(),
                message: e.to_string(),
            },
        }
    }
}

/// The error the system reported, or [`RngError::Unexpected`] when it
/// reported none.
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_vendor = "apple",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
fn os_error(err: &std::io::Error) -> RngError {
    err.raw_os_error()
        .map_or(RngError::Unexpected, RngError::Os)
}

/// Fills `buf` with bytes from the operating system's cryptographically
/// secure random number generator.
///
/// # Errors
///
/// [`RngError::Unsupported`] on a target without a source, and
/// [`RngError::Os`] if the system call fails. On error the contents of `buf`
/// are unspecified and must not be used.
pub fn fill(buf: &mut [u8]) -> Result<(), RngError> {
    imp::fill(buf)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod imp {
    use core::ffi::{c_uint, c_void};

    use super::{RngError, os_error};

    unsafe extern "C" {
        /// `ssize_t getrandom(void *buf, size_t buflen, unsigned int flags)`,
        /// glibc 2.25 and later, musl 1.1.20 and later, Android API level 28
        /// (Android 9) and later (see the module documentation).
        fn getrandom(buf: *mut c_void, buflen: usize, flags: c_uint) -> isize;
    }

    pub(super) fn fill(buf: &mut [u8]) -> Result<(), RngError> {
        let mut rest = buf;
        while !rest.is_empty() {
            // SAFETY: `rest` is a live, exclusively borrowed region of exactly
            // `rest.len()` writable bytes for the duration of the call, and
            // getrandom writes at most `buflen` bytes. Flags 0 reads the
            // urandom source and blocks only until it has been seeded.
            let n =
                unsafe { getrandom(rest.as_mut_ptr().cast(), rest.len(), 0) };
            if n < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(os_error(&err));
            }
            // A large request may be served in parts; continue after them.
            let n = usize::try_from(n).map_err(|_| RngError::Unexpected)?;
            rest = rest.get_mut(n..).ok_or(RngError::Unexpected)?;
        }
        Ok(())
    }
}

#[cfg(any(
    target_vendor = "apple",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
mod imp {
    use core::ffi::{c_int, c_void};

    use super::{RngError, os_error};

    /// `getentropy` refuses requests above 256 bytes.
    const MAX: usize = 256;

    unsafe extern "C" {
        /// `int getentropy(void *buffer, size_t length)`.
        fn getentropy(buffer: *mut c_void, length: usize) -> c_int;
    }

    pub(super) fn fill(buf: &mut [u8]) -> Result<(), RngError> {
        for chunk in buf.chunks_mut(MAX) {
            // SAFETY: `chunk` is a live, exclusively borrowed region of
            // `chunk.len() <= 256` writable bytes, the limit getentropy
            // accepts, and getentropy writes exactly that many bytes or fails.
            let r =
                unsafe { getentropy(chunk.as_mut_ptr().cast(), chunk.len()) };
            if r != 0 {
                return Err(os_error(&std::io::Error::last_os_error()));
            }
        }
        Ok(())
    }
}

#[cfg(windows)]
mod imp {
    use core::ffi::c_void;

    use baldssl_core::num::u32_to_usize;

    use super::RngError;

    /// Use the system's default generator; the algorithm handle is then NULL.
    const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;

    #[link(name = "bcrypt")]
    unsafe extern "system" {
        /// `NTSTATUS BCryptGenRandom(BCRYPT_ALG_HANDLE hAlgorithm,
        /// PUCHAR pbBuffer, ULONG cbBuffer, ULONG dwFlags)`.
        fn BCryptGenRandom(
            algorithm: *mut c_void,
            buffer: *mut u8,
            length: u32,
            flags: u32,
        ) -> i32;
    }

    pub(super) fn fill(buf: &mut [u8]) -> Result<(), RngError> {
        // The length is a 32-bit ULONG.
        for chunk in buf.chunks_mut(u32_to_usize(u32::MAX)) {
            let length =
                u32::try_from(chunk.len()).map_err(|_| RngError::Unexpected)?;
            // SAFETY: `chunk` is a live, exclusively borrowed region of
            // `length` writable bytes; with BCRYPT_USE_SYSTEM_PREFERRED_RNG
            // the algorithm handle must be NULL, which it is.
            let status = unsafe {
                BCryptGenRandom(
                    core::ptr::null_mut(),
                    chunk.as_mut_ptr(),
                    length,
                    BCRYPT_USE_SYSTEM_PREFERRED_RNG,
                )
            };
            if status != 0 {
                return Err(RngError::Os(status));
            }
        }
        Ok(())
    }
}

#[cfg(all(target_os = "wasi", target_env = "p1"))]
mod imp {
    use super::RngError;

    #[link(wasm_import_module = "wasi_snapshot_preview1")]
    unsafe extern "C" {
        /// `random_get(buf: Pointer<u8>, buf_len: Size) -> Result<(), Errno>`;
        /// the errno is 0 on success.
        fn random_get(buf: *mut u8, buf_len: usize) -> u16;
    }

    pub(super) fn fill(buf: &mut [u8]) -> Result<(), RngError> {
        // SAFETY: `buf` is a live, exclusively borrowed region of `buf.len()`
        // writable bytes in the module's memory, which random_get fills.
        let errno = unsafe { random_get(buf.as_mut_ptr(), buf.len()) };
        if errno == 0 {
            Ok(())
        } else {
            Err(RngError::Os(i32::from(errno)))
        }
    }
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_vendor = "apple",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
    windows,
    all(target_os = "wasi", target_env = "p1")
)))]
mod imp {
    use super::RngError;

    pub(super) fn fill(_buf: &mut [u8]) -> Result<(), RngError> {
        Err(RngError::Unsupported)
    }
}

#[cfg(all(
    test,
    any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
        windows,
        all(target_os = "wasi", target_env = "p1")
    )
))]
mod tests {
    use super::*;

    #[test]
    fn empty_and_small() {
        fill(&mut []).unwrap();
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        fill(&mut a).unwrap();
        fill(&mut b).unwrap();
        // Two 256-bit draws collide with probability 2^-256.
        assert_ne!(a, b);
    }

    /// Lengths around the 256-byte limit of getentropy, which the code
    /// splits into several calls.
    #[test]
    fn chunk_boundaries() {
        for len in [255, 256, 257, 511, 512, 513, 1000] {
            let mut buf = vec![0u8; len];
            fill(&mut buf).unwrap();
            // The tail is written too: 16 zero bytes in a row has
            // probability 2^-128.
            assert!(buf[len - 16..].iter().any(|&b| b != 0), "len {len}");
        }
    }

    /// A loose sanity check, not a statistical test of the generator: in
    /// 1 MiB, each byte value appears 4096 times on average with standard
    /// deviation about 64, so 9 standard deviations either way catches a
    /// broken source (constant, or bytes left unwritten) and never fails a
    /// working one in practice.
    #[test]
    fn byte_frequencies() {
        let mut buf = vec![0u8; 1 << 20];
        fill(&mut buf).unwrap();
        let mut counts = [0u32; 256];
        for &b in &buf {
            counts[usize::from(b)] += 1;
        }
        for (value, &count) in counts.iter().enumerate() {
            assert!((3500..=4700).contains(&count), "{value}: {count}");
        }
    }
}
