//! Object names exactly as OpenSSL prints them.
//!
//! The table is generated from OpenSSL's `obj_mac.h` by
//! `scripts/gen-objects.py` (see `make objects`).

use crate::objects_table::OBJECTS;
use baldssl_core::{Result, der::Oid};

fn cmp_dotted(a: &str, b: &str) -> core::cmp::Ordering {
    let mut lhs = a.split('.');
    let mut rhs = b.split('.');
    loop {
        match (lhs.next(), rhs.next()) {
            (None, None) => return core::cmp::Ordering::Equal,
            (None, Some(_)) => return core::cmp::Ordering::Less,
            (Some(_), None) => return core::cmp::Ordering::Greater,
            (Some(l), Some(r)) => {
                let ord = l.len().cmp(&r.len()).then_with(|| l.cmp(r));
                if ord != core::cmp::Ordering::Equal {
                    return ord;
                }
            }
        }
    }
}

fn find(dotted: &str) -> Option<(&'static str, &'static str)> {
    OBJECTS
        .binary_search_by(|(d, _, _)| cmp_dotted(d, dotted))
        .ok()
        .and_then(|i| OBJECTS.get(i))
        .map(|(_, sn, ln)| (*sn, *ln))
}

/// `OBJ_nid2sn`, falling back to the dotted form like `OBJ_obj2txt(.., 1)`.
///
/// # Errors
///
/// When the OID cannot be rendered (see [`Oid::to_dotted`]).
pub fn short_name(oid: &Oid<'_>) -> Result<String> {
    let dotted = oid.to_dotted()?;
    Ok(find(&dotted).map_or(dotted, |(sn, _)| sn.to_string()))
}

/// `i2a_ASN1_OBJECT` / `OBJ_obj2txt(.., 0)`: the long name if OpenSSL knows
/// the object, else the dotted form.
///
/// # Errors
///
/// When the OID cannot be rendered (see [`Oid::to_dotted`]).
pub fn long_name(oid: &Oid<'_>) -> Result<String> {
    let dotted = oid.to_dotted()?;
    Ok(find(&dotted).map_or(dotted, |(_, ln)| ln.to_string()))
}

/// Whether OpenSSL has this object in its table.
#[must_use]
pub fn is_known(dotted: &str) -> bool {
    find(dotted).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_is_sorted() {
        for pair in OBJECTS.windows(2) {
            assert_eq!(
                cmp_dotted(pair[0].0, pair[1].0),
                core::cmp::Ordering::Less,
                "{} !< {}",
                pair[0].0,
                pair[1].0
            );
        }
    }

    #[test]
    fn lookups() {
        assert_eq!(
            find("1.2.840.113549.1.1.11"),
            Some(("RSA-SHA256", "sha256WithRSAEncryption"))
        );
        assert_eq!(find("2.5.4.3"), Some(("CN", "commonName")));
        assert_eq!(find("1.2.3.4.5"), None);
        let oid = Oid::parse(&[0x2a, 0x03, 0x04, 0x05]).unwrap();
        assert_eq!(long_name(&oid).unwrap(), "1.2.3.4.5");
    }
}
