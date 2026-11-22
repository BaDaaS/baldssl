//! Canonical encodings, as traits.
//!
//! The two directions are separate traits, because they have different
//! shapes (encoding takes `&self`, decoding is a constructor that may fail)
//! and a type may need only one.
//!
//! # The laws
//!
//! When `decode(encode(x)) = x`, `encode` is a section and `decode` a
//! retraction: the type is a retract of the byte strings. Then
//! $e = \mathrm{encode} \circ \mathrm{decode}$ is an idempotent partial map on
//! byte strings, and the canonical encodings are exactly its fixed points.
//! The round trip makes $e$ the identity on the image of `encode` for free;
//! *canonicity* is the stronger claim that $e$ is the identity on everything
//! `decode` accepts, so no second spelling of a value decodes (as BER does
//! for DER). It quantifies over arbitrary byte strings, not over values, so
//! it is tested separately.
//!
//! Coherence allows one implementation per type, so a type has one encoding
//! here. A second encoding of the same values (SEC 1's compressed points)
//! needs a newtype to carry it: the newtype is where the second idempotent
//! lives.
//!
//! Decoding takes no context: points are self-describing.
//!
//! A curve model's encoding is that of its representation: the affine chart
//! encodes points in the standard formats (SEC 1, RFC 8032), while the
//! projective, Jacobian and extended models encode their coordinates, so two
//! representatives of one point encode differently. The laws hold for each
//! with equality of points: decoding an encoding gives back the same point,
//! and canonicity holds because encoding writes back the exact
//! representation that was decoded.

/// A canonical encoding.
pub trait Encodable {
    /// The encoded form: a fixed-size array when the length is fixed.
    type Bytes: AsRef<[u8]>;

    /// The canonical encoding of `self`.
    fn encode(&self) -> Self::Bytes;
}

/// Decoding of a canonical encoding.
pub trait Decodable: Sized {
    /// The value whose canonical encoding is `bytes`, or `None` if `bytes`
    /// is not one.
    fn decode(bytes: &[u8]) -> Option<Self>;
}
