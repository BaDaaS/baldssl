//! Object names exactly as OpenSSL prints them.
//!
//! The table is generated from OpenSSL's `obj_mac.h` by
//! `scripts/gen-objects.py` (see `make objects`).

use crate::objects_table::OBJECTS;
use baldssl_core::{
    Result,
    der::{Oid, syntax::ObjectId},
};

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

fn find_opt(dotted: &str) -> Option<(&'static str, &'static str)> {
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
pub(crate) fn short_name(oid: &Oid<'_>) -> Result<String> {
    let dotted = oid.to_dotted()?;
    Ok(find_opt(&dotted).map_or(dotted, |(sn, _)| sn.to_string()))
}

/// `i2a_ASN1_OBJECT` / `OBJ_obj2txt(.., 0)`: the long name if OpenSSL knows
/// the object, else the dotted form.
///
/// # Errors
///
/// When the OID cannot be rendered (see [`Oid::to_dotted`]).
pub(crate) fn long_name(oid: &Oid<'_>) -> Result<String> {
    let dotted = oid.to_dotted()?;
    Ok(find_opt(&dotted).map_or(dotted, |(_, ln)| ln.to_string()))
}

/// The identifier of a table entry's dotted form, `None` for the three
/// roots `itu-t` (0), `iso` (1) and `joint-iso-itu-t` (2): an OBJECT
/// IDENTIFIER has at least two arcs ([X.690] 8.19.4), so these have no
/// encoding, in OpenSSL as here. Every other entry has one
/// (`entries_are_identifiers` tests the whole table).
///
/// [X.690]: https://www.itu.int/rec/T-REC-X.690
fn entry_oid_opt(dotted: &str) -> Option<ObjectId> {
    ObjectId::from_dotted_opt(dotted)
}

/// Whether a short name, a long name or a dotted OID is in OpenSSL's table,
/// as `OBJ_txt2nid` finds it, encodable or not.
#[must_use]
pub(crate) fn is_name(text: &str) -> bool {
    OBJECTS
        .iter()
        .any(|(d, sn, ln)| *sn == text || *ln == text || *d == text)
}

/// The object of a short name only, as OpenSSL's `OBJ_sn2nid` finds it: how
/// a configuration names an extension.
pub(crate) fn find_by_short_name_opt(text: &str) -> Option<ObjectId> {
    OBJECTS
        .iter()
        .find(|(_, sn, _)| *sn == text)
        .and_then(|(d, _, _)| entry_oid_opt(d))
}

/// `OBJ_txt2nid`: the object a short name, a long name, or a dotted OID
/// names, in that order, when OpenSSL has it in its table and it has an
/// encoding (see [`entry_oid_opt`]). Names are case-sensitive, as in
/// OpenSSL.
#[must_use]
pub(crate) fn find_by_name_opt(text: &str) -> Option<ObjectId> {
    OBJECTS
        .iter()
        .find(|(_, sn, _)| *sn == text)
        .or_else(|| OBJECTS.iter().find(|(_, _, ln)| *ln == text))
        .or_else(|| OBJECTS.iter().find(|(d, _, _)| *d == text))
        .and_then(|(d, _, _)| entry_oid_opt(d))
}

/// Whether OpenSSL has this object in its table. An identifier without a
/// dotted form (an arc of 2^128 or more, see [`Oid::to_dotted`]) is not in
/// it: every entry has one.
#[must_use]
pub(crate) fn is_known(oid: &Oid<'_>) -> bool {
    oid.to_dotted()
        .is_ok_and(|dotted| find_opt(&dotted).is_some())
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

    /// Every entry's dotted form is an object identifier, which the
    /// lookups' conversion relies on.
    #[test]
    fn entries_are_identifiers() {
        for (dotted, _, _) in OBJECTS {
            let root = !dotted.contains('.');
            assert_eq!(entry_oid_opt(dotted).is_none(), root, "{dotted}");
        }
        assert!(is_name("ISO") && find_by_name_opt("ISO").is_none());
    }

    #[test]
    fn lookups() {
        assert_eq!(
            find_opt("1.2.840.113549.1.1.11"),
            Some(("RSA-SHA256", "sha256WithRSAEncryption"))
        );
        assert_eq!(find_opt("2.5.4.3"), Some(("CN", "commonName")));
        assert_eq!(find_opt("1.2.3.4.5"), None);
        let oid = Oid::parse(&[0x2a, 0x03, 0x04, 0x05]).unwrap();
        assert_eq!(long_name(&oid).unwrap(), "1.2.3.4.5");
        assert!(!is_known(&oid));
        assert_eq!(
            find_by_short_name_opt("keyUsage"),
            ObjectId::from_dotted_opt("2.5.29.15")
        );
        assert_eq!(find_by_short_name_opt("X509v3 Key Usage"), None);
        assert_eq!(
            find_by_name_opt("X509v3 Key Usage"),
            ObjectId::from_dotted_opt("2.5.29.15")
        );
        assert_eq!(
            find_by_name_opt("2.5.29.15"),
            ObjectId::from_dotted_opt("2.5.29.15")
        );
    }
}
