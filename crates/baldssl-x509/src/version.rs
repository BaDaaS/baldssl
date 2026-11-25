//! The certificate version, `version [0] EXPLICIT Version DEFAULT v1` with
//! `Version ::= INTEGER { v1(0), v2(1), v3(2) }` ([RFC 5280 section
//! 4.1.2.1][rfc5280-4.1.2.1]).
//!
//! The field is read as OpenSSL reads it, not as DER requires it. DER omits
//! a field equal to its default ([X.690] 11.5), so a v1 certificate has no
//! version field; OpenSSL also accepts an explicit `[0] INTEGER 0`, and
//! any INTEGER as the version, printed as `Unknown (n)`. The description is
//! therefore an OPTIONAL `[0] EXPLICIT INTEGER` of any value: absent and
//! explicit v1 are distinct values, each re-encoding to itself, so the
//! description keeps the laws of `der::syntax`.
//!
//! [rfc5280-4.1.2.1]: https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.1
//! [X.690]: https://www.itu.int/rec/T-REC-X.690

use baldssl_core::der::{
    Integer,
    syntax::{Explicit, Map, Optional, Signed},
};

/// The stored value of `v3`, the last version [RFC 5280 section 4.1]
/// names.
///
/// [RFC 5280 section 4.1]: https://www.rfc-editor.org/rfc/rfc5280#section-4.1
const V3: u8 = 2;

/// A certificate version: the INTEGER of the version field, of any value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Version(Integer);

impl Version {
    /// v1, the value of an absent version field.
    #[must_use]
    pub(crate) fn v1() -> Self {
        Version(Integer::from(0))
    }

    /// v3, the version of a certificate with extensions.
    #[must_use]
    pub(crate) fn v3() -> Self {
        Version(Integer::from(i64::from(V3)))
    }

    /// The INTEGER as stored: 0 for v1, 1 for v2, 2 for v3.
    #[must_use]
    pub(crate) fn as_integer(&self) -> &Integer {
        &self.0
    }

    /// The stored value when it is one of v1, v2 and v3 (0, 1 or 2).
    #[must_use]
    pub(crate) fn known_opt(&self) -> Option<u8> {
        self.0
            .to_u64_opt()
            .and_then(|n| u8::try_from(n).ok())
            .filter(|&n| n <= V3)
    }
}

/// The version field: absent (`None`, which means v1) or present.
pub(crate) type VersionField = Optional<Explicit<0, Map<Signed, Version>>>;

/// The description of the version field.
pub(crate) fn version_field() -> VersionField {
    Optional(Explicit(Map::new(
        Signed,
        |int| Some(Version(int)),
        |version| version.0.clone(),
    )))
}

#[cfg(test)]
mod tests;
