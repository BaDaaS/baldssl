//! The OpenSSL release line this build of baldssl imitates.
//!
//! The line is chosen when baldssl is built, by exactly one of its Cargo
//! features, `openssl-3-0`, `openssl-3-5` (the default), `openssl-3-6` or
//! `openssl-4`: a binary imitates one release line, and [`Line`] is its
//! [`Profile`]. The library, `baldssl-x509`, can compile several lines at
//! once (its tests check each); the binary is a leaf, so its features are
//! not unified with any other crate's and can exclude each other.

#[cfg(not(any(
    all(
        feature = "openssl-3-0",
        not(feature = "openssl-3-5"),
        not(feature = "openssl-3-6"),
        not(feature = "openssl-4")
    ),
    all(
        feature = "openssl-3-5",
        not(feature = "openssl-3-0"),
        not(feature = "openssl-3-6"),
        not(feature = "openssl-4")
    ),
    all(
        feature = "openssl-3-6",
        not(feature = "openssl-3-0"),
        not(feature = "openssl-3-5"),
        not(feature = "openssl-4")
    ),
    all(
        feature = "openssl-4",
        not(feature = "openssl-3-0"),
        not(feature = "openssl-3-5"),
        not(feature = "openssl-3-6")
    ),
)))]
compile_error!(
    "baldssl imitates one OpenSSL release line: enable exactly one of the \
     features openssl-3-0, openssl-3-5, openssl-3-6 and openssl-4"
);

use baldssl_x509::{Compat, Profile};

/// The release line this build imitates: OpenSSL 3.0.
#[cfg(feature = "openssl-3-0")]
pub(crate) type Line = baldssl_x509::OpenSsl30;

/// The release line this build imitates: OpenSSL 3.5.
#[cfg(all(feature = "openssl-3-5", not(feature = "openssl-3-0")))]
pub(crate) type Line = baldssl_x509::OpenSsl35;

/// The release line this build imitates: OpenSSL 3.6.
#[cfg(all(
    feature = "openssl-3-6",
    not(feature = "openssl-3-0"),
    not(feature = "openssl-3-5")
))]
pub(crate) type Line = baldssl_x509::OpenSsl36;

/// The release line this build imitates: OpenSSL 4.
#[cfg(all(
    feature = "openssl-4",
    not(feature = "openssl-3-0"),
    not(feature = "openssl-3-5"),
    not(feature = "openssl-3-6")
))]
pub(crate) type Line = baldssl_x509::OpenSsl4;

/// The release line, for the modules that still ask [`Compat`]'s methods.
pub(crate) const fn compat() -> Compat {
    Line::COMPAT
}
