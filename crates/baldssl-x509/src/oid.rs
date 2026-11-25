//! The object identifiers baldssl's X.509 code compares against, each with
//! its dotted form and the standard that assigns it. Code matches a decoded
//! [`baldssl_core::der::Oid`] against these values (`oid == ID_CE_KEY_USAGE`),
//! never its dotted text.

use baldssl_core::der::syntax::ObjectId;

/// `id-ce-subjectKeyIdentifier`, 2.5.29.14 ([RFC 5280 section 4.2.1.2]).
///
/// [RFC 5280 section 4.2.1.2]: https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.2
pub(crate) const ID_CE_SUBJECT_KEY_IDENTIFIER: ObjectId =
    ObjectId::from_static(&[0x55, 0x1d, 0x0e]);
/// `id-ce-keyUsage`, 2.5.29.15 ([RFC 5280 section 4.2.1.3]).
///
/// [RFC 5280 section 4.2.1.3]: https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.3
pub(crate) const ID_CE_KEY_USAGE: ObjectId =
    ObjectId::from_static(&[0x55, 0x1d, 0x0f]);
/// `id-ce-subjectAltName`, 2.5.29.17 ([RFC 5280 section 4.2.1.6]).
///
/// [RFC 5280 section 4.2.1.6]: https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.6
pub(crate) const ID_CE_SUBJECT_ALT_NAME: ObjectId =
    ObjectId::from_static(&[0x55, 0x1d, 0x11]);
/// `id-ce-issuerAltName`, 2.5.29.18 ([RFC 5280 section 4.2.1.7]).
///
/// [RFC 5280 section 4.2.1.7]: https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.7
pub(crate) const ID_CE_ISSUER_ALT_NAME: ObjectId =
    ObjectId::from_static(&[0x55, 0x1d, 0x12]);
/// `id-ce-basicConstraints`, 2.5.29.19 ([RFC 5280 section 4.2.1.9]).
///
/// [RFC 5280 section 4.2.1.9]: https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.9
pub(crate) const ID_CE_BASIC_CONSTRAINTS: ObjectId =
    ObjectId::from_static(&[0x55, 0x1d, 0x13]);
/// `id-ce-nameConstraints`, 2.5.29.30 ([RFC 5280 section 4.2.1.10]).
///
/// [RFC 5280 section 4.2.1.10]: https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.10
pub(crate) const ID_CE_NAME_CONSTRAINTS: ObjectId =
    ObjectId::from_static(&[0x55, 0x1d, 0x1e]);
/// `id-ce-certificatePolicies`, 2.5.29.32 ([RFC 5280 section 4.2.1.4]).
///
/// [RFC 5280 section 4.2.1.4]: https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.4
pub(crate) const ID_CE_CERTIFICATE_POLICIES: ObjectId =
    ObjectId::from_static(&[0x55, 0x1d, 0x20]);
/// `id-ce-policyMappings`, 2.5.29.33 ([RFC 5280 section 4.2.1.5]).
///
/// [RFC 5280 section 4.2.1.5]: https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.5
pub(crate) const ID_CE_POLICY_MAPPINGS: ObjectId =
    ObjectId::from_static(&[0x55, 0x1d, 0x21]);
/// `id-ce-authorityKeyIdentifier`, 2.5.29.35 ([RFC 5280 section 4.2.1.1]).
///
/// [RFC 5280 section 4.2.1.1]: https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.1
pub(crate) const ID_CE_AUTHORITY_KEY_IDENTIFIER: ObjectId =
    ObjectId::from_static(&[0x55, 0x1d, 0x23]);
/// `id-ce-policyConstraints`, 2.5.29.36 ([RFC 5280 section 4.2.1.11]).
///
/// [RFC 5280 section 4.2.1.11]: https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.11
pub(crate) const ID_CE_POLICY_CONSTRAINTS: ObjectId =
    ObjectId::from_static(&[0x55, 0x1d, 0x24]);
/// `id-ce-extKeyUsage`, 2.5.29.37 ([RFC 5280 section 4.2.1.12]).
///
/// [RFC 5280 section 4.2.1.12]: https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.12
pub(crate) const ID_CE_EXT_KEY_USAGE: ObjectId =
    ObjectId::from_static(&[0x55, 0x1d, 0x25]);
/// `id-ce-inhibitAnyPolicy`, 2.5.29.54 ([RFC 5280 section 4.2.1.14]).
///
/// [RFC 5280 section 4.2.1.14]: https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.14
pub(crate) const ID_CE_INHIBIT_ANY_POLICY: ObjectId =
    ObjectId::from_static(&[0x55, 0x1d, 0x36]);
/// `netscape-cert-type`, 2.16.840.1.113730.1.1 (OpenSSL's
/// `NID_netscape_cert_type`, `crypto/objects/objects.txt`).
pub(crate) const NETSCAPE_CERT_TYPE: ObjectId = ObjectId::from_static(&[
    0x60, 0x86, 0x48, 0x01, 0x86, 0xf8, 0x42, 0x01, 0x01,
]);
/// `id-pe-ipAddrBlocks`, 1.3.6.1.5.5.7.1.7 ([RFC 3779 section 2.2.1]).
///
/// [RFC 3779 section 2.2.1]: https://www.rfc-editor.org/rfc/rfc3779#section-2.2.1
pub(crate) const ID_PE_IP_ADDR_BLOCKS: ObjectId =
    ObjectId::from_static(&[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x07]);
/// `id-pe-autonomousSysIds`, 1.3.6.1.5.5.7.1.8 ([RFC 3779 section 3.2.1]).
///
/// [RFC 3779 section 3.2.1]: https://www.rfc-editor.org/rfc/rfc3779#section-3.2.1
pub(crate) const ID_PE_AUTONOMOUS_SYS_IDS: ObjectId =
    ObjectId::from_static(&[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x08]);
/// `id-pe-proxyCertInfo`, 1.3.6.1.5.5.7.1.14 ([RFC 3820 section 3.8]).
///
/// [RFC 3820 section 3.8]: https://www.rfc-editor.org/rfc/rfc3820#section-3.8
pub(crate) const ID_PE_PROXY_CERT_INFO: ObjectId =
    ObjectId::from_static(&[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x0e]);

/// `rsaEncryption`, 1.2.840.113549.1.1.1 ([RFC 8017 appendix C]).
///
/// [RFC 8017 appendix C]: https://www.rfc-editor.org/rfc/rfc8017#appendix-C
pub(crate) const RSA_ENCRYPTION: ObjectId = ObjectId::from_static(&[
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
]);
/// `id-RSASSA-PSS`, 1.2.840.113549.1.1.10 ([RFC 8017 appendix C]).
///
/// [RFC 8017 appendix C]: https://www.rfc-editor.org/rfc/rfc8017#appendix-C
pub(crate) const ID_RSASSA_PSS: ObjectId = ObjectId::from_static(&[
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a,
]);
/// `SM2-with-SM3`, 1.2.156.10197.1.501 (GM/T 0006; OpenSSL's
/// `NID_SM2_with_SM3`, `crypto/objects/objects.txt`).
pub(crate) const SM2_WITH_SM3: ObjectId =
    ObjectId::from_static(&[0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x83, 0x75]);
/// `id-ecPublicKey`, 1.2.840.10045.2.1 ([RFC 5480 section 2.1.1]).
///
/// [RFC 5480 section 2.1.1]: https://www.rfc-editor.org/rfc/rfc5480#section-2.1.1
pub(crate) const ID_EC_PUBLIC_KEY: ObjectId =
    ObjectId::from_static(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]);
/// `id-Ed25519`, 1.3.101.112 ([RFC 8410 section 3]).
///
/// [RFC 8410 section 3]: https://www.rfc-editor.org/rfc/rfc8410#section-3
pub(crate) const ID_ED25519: ObjectId =
    ObjectId::from_static(&[0x2b, 0x65, 0x70]);
/// `prime256v1` (`secp256r1`), 1.2.840.10045.3.1.7
/// ([RFC 5480 section 2.1.1.1]).
///
/// [RFC 5480 section 2.1.1.1]: https://www.rfc-editor.org/rfc/rfc5480#section-2.1.1.1
pub(crate) const PRIME256V1: ObjectId =
    ObjectId::from_static(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]);
/// `secp384r1`, 1.3.132.0.34 ([RFC 5480 section 2.1.1.1]).
///
/// [RFC 5480 section 2.1.1.1]: https://www.rfc-editor.org/rfc/rfc5480#section-2.1.1.1
pub(crate) const SECP384R1: ObjectId =
    ObjectId::from_static(&[0x2b, 0x81, 0x04, 0x00, 0x22]);
/// `secp521r1`, 1.3.132.0.35 ([RFC 5480 section 2.1.1.1]).
///
/// [RFC 5480 section 2.1.1.1]: https://www.rfc-editor.org/rfc/rfc5480#section-2.1.1.1
pub(crate) const SECP521R1: ObjectId =
    ObjectId::from_static(&[0x2b, 0x81, 0x04, 0x00, 0x23]);

/// `pkcs-9-at-extensionRequest`, 1.2.840.113549.1.9.14
/// ([RFC 2985 section 5.4.2]).
///
/// [RFC 2985 section 5.4.2]: https://www.rfc-editor.org/rfc/rfc2985#section-5
pub(crate) const EXTENSION_REQUEST: ObjectId = ObjectId::from_static(&[
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x0e,
]);

#[cfg(test)]
mod tests {
    use super::*;

    /// Each constant's contents are the dotted form its documentation gives.
    #[test]
    fn dotted_forms() {
        for (oid, dotted) in [
            (&ID_CE_SUBJECT_KEY_IDENTIFIER, "2.5.29.14"),
            (&ID_CE_KEY_USAGE, "2.5.29.15"),
            (&ID_CE_SUBJECT_ALT_NAME, "2.5.29.17"),
            (&ID_CE_ISSUER_ALT_NAME, "2.5.29.18"),
            (&ID_CE_BASIC_CONSTRAINTS, "2.5.29.19"),
            (&ID_CE_NAME_CONSTRAINTS, "2.5.29.30"),
            (&ID_CE_CERTIFICATE_POLICIES, "2.5.29.32"),
            (&ID_CE_POLICY_MAPPINGS, "2.5.29.33"),
            (&ID_CE_AUTHORITY_KEY_IDENTIFIER, "2.5.29.35"),
            (&ID_CE_POLICY_CONSTRAINTS, "2.5.29.36"),
            (&ID_CE_EXT_KEY_USAGE, "2.5.29.37"),
            (&ID_CE_INHIBIT_ANY_POLICY, "2.5.29.54"),
            (&NETSCAPE_CERT_TYPE, "2.16.840.1.113730.1.1"),
            (&ID_PE_IP_ADDR_BLOCKS, "1.3.6.1.5.5.7.1.7"),
            (&ID_PE_AUTONOMOUS_SYS_IDS, "1.3.6.1.5.5.7.1.8"),
            (&ID_PE_PROXY_CERT_INFO, "1.3.6.1.5.5.7.1.14"),
            (&RSA_ENCRYPTION, "1.2.840.113549.1.1.1"),
            (&ID_RSASSA_PSS, "1.2.840.113549.1.1.10"),
            (&SM2_WITH_SM3, "1.2.156.10197.1.501"),
            (&ID_EC_PUBLIC_KEY, "1.2.840.10045.2.1"),
            (&ID_ED25519, "1.3.101.112"),
            (&PRIME256V1, "1.2.840.10045.3.1.7"),
            (&SECP384R1, "1.3.132.0.34"),
            (&SECP521R1, "1.3.132.0.35"),
            (&EXTENSION_REQUEST, "1.2.840.113549.1.9.14"),
        ] {
            assert_eq!(oid.to_dotted().unwrap(), dotted);
        }
    }
}
