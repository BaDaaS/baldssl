//! proptest generators shared by the test suites. They produce plain data
//! (bytes, dotted object identifiers) rather than baldssl types, so this
//! crate depends on no other baldssl crate and any of them can use it.

use core::fmt::Write as _;

use proptest::{collection::vec, prelude::*};

/// Byte strings of length 0 to `max - 1`.
pub fn bytes(max: usize) -> impl Strategy<Value = Vec<u8>> {
    vec(any::<u8>(), 0..max)
}

/// Byte strings of length 0 to `max - 1` whose first octet, if any, is not
/// `tag`: what may follow an OPTIONAL or DEFAULT field with that tag without
/// being read as the field.
pub fn bytes_not_starting_with(
    tag: u8,
    max: usize,
) -> impl Strategy<Value = Vec<u8>> {
    bytes(max).prop_filter("starts with the field's tag", move |b| {
        b.first() != Some(&tag)
    })
}

/// Object identifiers in dotted form: a first arc of 0 to 2, a second arc
/// below 40 (as [X.690] clause 8.19.4 requires for the first two arcs to
/// share a subidentifier), then up to five more arcs.
///
/// [X.690]: https://www.itu.int/rec/T-REC-X.690
pub fn dotted_oid() -> impl Strategy<Value = String> {
    (0u64..=2, 0u64..40, vec(any::<u32>(), 0..6)).prop_map(|(a, b, rest)| {
        let mut dotted = format!("{a}.{b}");
        for arc in rest {
            // Writing to a String cannot fail.
            let _ = write!(dotted, ".{arc}");
        }
        dotted
    })
}

/// INTEGER values as a sign and a big-endian magnitude without leading
/// zeros, of up to `max - 1` octets, never a negative zero: the form of a
/// parsed DER INTEGER.
pub fn sign_magnitude(max: usize) -> impl Strategy<Value = (bool, Vec<u8>)> {
    (any::<bool>(), bytes(max)).prop_map(|(negative, m)| {
        let first = m.iter().position(|&b| b != 0).unwrap_or(m.len());
        let magnitude = m.get(first..).unwrap_or_default().to_vec();
        (negative && !magnitude.is_empty(), magnitude)
    })
}
