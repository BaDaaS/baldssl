//! Message authentication codes: HMAC ([RFC 2104]) over SHA-1 and SHA-2.
//!
//! A MAC is a keyed family of functions from messages to tags. [`Mac`] is
//! that interface, incremental like [`Digest`]: feeding a message in pieces
//! gives the tag of the concatenation, the same right action of the free
//! monoid of byte strings as for a hash. [`Hmac`] is the construction of
//! RFC 2104 section 2,
//!
//! $$\mathrm{HMAC}(K, m) = H((K' \oplus \mathrm{opad}) \,\|\, H((K' \oplus
//! \mathrm{ipad}) \,\|\, m)),$$
//!
//! where $K'$ is the key padded with zeros to the block length $B$ of $H$,
//! after hashing it first when it is longer than $B$.
//!
//! Tags are [`Tag`]s, compared in constant time.
//!
//! [RFC 2104]: https://www.rfc-editor.org/rfc/rfc2104#section-2

use crate::{
    ct::{Choice, CtEq},
    drbg::DrbgHash,
    hash::{Algorithm, Digest, WithHash},
    secret::SecretBytes,
};

/// The inner padding byte of RFC 2104 section 2.
const IPAD: u8 = 0x36;
/// The outer padding byte of RFC 2104 section 2.
const OPAD: u8 = 0x5c;

/// A message authentication code: a key fixed at creation, the message fed
/// in pieces.
///
/// Laws, checked for [`Hmac`] over every hash: feeding `a` then `b` gives
/// the tag of `a || b`; [`Mac::mac`] is [`Mac::new`], one
/// [`Mac::update`], then [`Mac::finalize`].
pub trait Mac: crate::sealed::Sealed + Sized {
    /// A computation keyed with `key`.
    #[must_use]
    fn new(key: &[u8]) -> Self;

    /// Absorbs more of the message.
    fn update(&mut self, data: &[u8]);

    /// The tag of the message absorbed.
    #[must_use]
    fn finalize(self) -> Tag;

    /// The tag of `message` under `key`, in one call.
    #[must_use]
    fn mac(key: &[u8], message: &[u8]) -> Tag {
        let mut m = Self::new(key);
        m.update(message);
        m.finalize()
    }
}

/// A MAC tag. It is public once computed, but comparing it with a tag an
/// attacker chose must not tell how many bytes matched, so equality is
/// constant time ([`CtEq`]), and `==` uses it.
#[derive(Clone)]
pub struct Tag(Vec<u8>);

impl Tag {
    /// The tag's bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Whether `candidate` is this tag, in time that depends only on the
    /// lengths. A truncated tag (RFC 2104 section 5) is checked by
    /// comparing with a prefix of this one.
    pub fn verify_ct(&self, candidate: &[u8]) -> Choice {
        self.0.as_slice().ct_eq(candidate)
    }

    /// The tag, as a secret: for a tag used as a key (HMAC_DRBG's `K` and
    /// `V`), so that it is wiped when dropped. The bytes are moved, not
    /// copied.
    pub(crate) fn into_secret(self) -> SecretBytes {
        SecretBytes::new(self.0)
    }
}

impl crate::sealed::Sealed for Tag {}

impl CtEq for Tag {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.as_slice().ct_eq(other.0.as_slice())
    }
}

impl PartialEq for Tag {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).to_bool_vartime()
    }
}

impl Eq for Tag {}

impl core::fmt::Debug for Tag {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Tag(")?;
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        write!(f, ")")
    }
}

/// HMAC over the hash `H` ([RFC 2104 section 2][rfc2104]). Constant time
/// in the key and the message; only their lengths, which are public, decide
/// any branch.
///
/// [rfc2104]: https://www.rfc-editor.org/rfc/rfc2104#section-2
pub struct Hmac<H>
where
    H: Digest,
{
    /// `H` with `K' xor ipad` absorbed, then the message.
    inner: H,
    /// `K' xor opad`, kept for [`Mac::finalize`].
    outer_pad: SecretBytes,
}

impl<H> Hmac<H>
where
    H: Digest,
{
    /// `K'`: the key, hashed first when longer than the block, then padded
    /// with zeros to the block length (RFC 2104 section 2, steps 1 and 2).
    /// Built in place in a buffer of the block length, so that no copy of
    /// the key is left in a reallocated vector.
    fn block_key(key: &[u8]) -> SecretBytes {
        let mut k = SecretBytes::filled(0, H::BLOCK_LEN);
        let hashed;
        let source = if key.len() > H::BLOCK_LEN {
            hashed = SecretBytes::new(H::digest(key));
            hashed.expose()
        } else {
            key
        };
        // The source is at most BLOCK_LEN bytes (a digest is shorter than a
        // block), so the zip copies all of it.
        for (dst, src) in k.expose_mut().iter_mut().zip(source) {
            *dst = *src;
        }
        k
    }

    /// `K' xor pad`, byte by byte.
    fn padded(block_key: &SecretBytes, pad: u8) -> SecretBytes {
        SecretBytes::new(block_key.expose().iter().map(|b| b ^ pad).collect())
    }
}

impl<H> crate::sealed::Sealed for Hmac<H> where H: Digest {}

impl<H> Mac for Hmac<H>
where
    H: Digest,
{
    fn new(key: &[u8]) -> Self {
        let block_key = Self::block_key(key);
        let mut inner = H::new();
        inner.update(Self::padded(&block_key, IPAD).expose());
        Hmac {
            inner,
            outer_pad: Self::padded(&block_key, OPAD),
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn finalize(self) -> Tag {
        let inner = SecretBytes::new(self.inner.finalize());
        let mut outer = H::new();
        outer.update(self.outer_pad.expose());
        outer.update(inner.expose());
        Tag(outer.finalize())
    }
}

impl Algorithm {
    /// The HMAC tag of `message` under `key` with the hash this names:
    /// [`Hmac::<H>`](Hmac) for the `H` of [`Algorithm::with`].
    #[must_use]
    pub fn hmac(self, key: &[u8], message: &[u8]) -> Tag {
        self.with(HmacWith { key, message })
    }
}

/// HMAC of a message, with any hash.
struct HmacWith<'a> {
    key: &'a [u8],
    message: &'a [u8],
}

impl WithHash for HmacWith<'_> {
    type Output = Tag;

    fn run<H>(self) -> Tag
    where
        H: DrbgHash,
    {
        Hmac::<H>::mac(self.key, self.message)
    }
}

#[cfg(test)]
mod tests;
