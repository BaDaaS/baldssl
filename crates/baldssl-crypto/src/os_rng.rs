//! Randomness from the operating system.
//!
//! This is the only module of baldssl allowed to use `unsafe`: stable Rust's
//! standard library exposes no source of cryptographic randomness, so the
//! operating system is called directly. `make check-unsafe` (in CI) fails if
//! `unsafe` code appears in any other file. Every call below is the system's
//! documented interface for cryptographic randomness:
//!
//! | Platform                     | Call                                                        |
//! | ---------------------------- | ----------------------------------------------------------- |
//! | Linux, Android               | `getrandom(2)`, flags 0: blocks until the pool is seeded   |
//! | macOS, iOS, FreeBSD, OpenBSD, NetBSD, DragonFly | `getentropy(2)`, at most 256 bytes per call |
//! | Windows                      | `BCryptGenRandom` with `BCRYPT_USE_SYSTEM_PREFERRED_RNG`    |
//! | WASI preview 1               | `random_get` from `wasi_snapshot_preview1`                  |
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
        }
    }
}

impl std::error::Error for RngError {}

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

    use super::RngError;

    unsafe extern "C" {
        /// `ssize_t getrandom(void *buf, size_t buflen, unsigned int flags)`,
        /// glibc 2.25 and later, musl, Android API 28 and later.
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
                return Err(RngError::Os(err.raw_os_error().unwrap_or(-1)));
            }
            // A large request may be served in parts; continue after them.
            let n = usize::try_from(n).map_err(|_| RngError::Os(-1))?;
            rest = rest.get_mut(n..).ok_or(RngError::Os(-1))?;
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

    use super::RngError;

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
                let err = std::io::Error::last_os_error();
                return Err(RngError::Os(err.raw_os_error().unwrap_or(-1)));
            }
        }
        Ok(())
    }
}

#[cfg(windows)]
mod imp {
    use core::ffi::c_void;

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
        for chunk in buf.chunks_mut(u32::MAX as usize) {
            let length =
                u32::try_from(chunk.len()).map_err(|_| RngError::Os(-1))?;
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
