//! REALITY temporary certificate handling.
//!
//! REALITY does not present a real CA-signed certificate.  Instead the server
//! holds a single long-lived Ed25519 key pair and a self-issued leaf certificate
//! for it.  Per connection it overwrites the certificate's 64-byte signature with
//! `HMAC-SHA512(auth_key, ed25519_public_key)`.  The uTLS client skips normal
//! chain verification and instead recomputes that HMAC, so a matching value
//! proves the peer possesses the REALITY private key (via the derived auth key).
//!
//! BoringSSL still performs a real TLS 1.3 handshake: it sends this certificate
//! verbatim and signs the CertificateVerify with the genuine Ed25519 private key.
//! It never validates the leaf's self-signature, so replacing those trailing
//! bytes is safe.
//!
//! The certificate DER is hand-built because boring's safe API cannot pass the
//! NULL digest that `X509_sign` requires for Ed25519, and the crate forbids
//! `unsafe`.  Only an Ed25519 SubjectPublicKeyInfo and a fixed 64-byte trailing
//! signature are needed, both of which are trivial to encode.

use boring::pkey::{Id, PKey, Private};
use std::io;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::crypto::certificate_signature;
use super::new_error;

/// The long-lived REALITY signing identity.
pub struct RealityCertificate {
    /// Ed25519 private key used for the TLS CertificateVerify.
    key: PKey<Private>,
    /// Raw 32-byte Ed25519 public key, HMAC input for the forged signature.
    public: [u8; 32],
    /// DER of the self-issued leaf certificate; last 64 bytes are the signature.
    base_der: Vec<u8>,
}

impl RealityCertificate {
    /// Generates a fresh Ed25519 identity and self-issued leaf certificate.
    pub fn generate() -> io::Result<Self> {
        let key = PKey::generate(Id::ED25519).map_err(new_error)?;
        let mut public = [0u8; 32];
        let raw = key.raw_public_key(&mut public).map_err(new_error)?;
        if raw.len() != 32 {
            return Err(new_error("unexpected Ed25519 public key length"));
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| new_error("system clock before unix epoch"))?
            .as_secs();
        let base_der = build_certificate(&public, now)?;
        if base_der.len() < 64 {
            return Err(new_error("generated certificate is too short"));
        }
        Ok(Self {
            key,
            public,
            base_der,
        })
    }

    /// The Ed25519 private key, for use as the TLS leaf key.
    pub fn private_key(&self) -> &PKey<Private> {
        &self.key
    }

    /// Builds the per-connection forged certificate DER for a given auth key.
    ///
    /// Returns the raw DER so the acceptor can install it directly; the trailing
    /// 64 signature bytes are replaced with `HMAC-SHA512(auth_key, ed25519_pub)`.
    pub fn forge(&self, auth_key: &[u8; 32]) -> io::Result<Vec<u8>> {
        let signature = certificate_signature(auth_key, &self.public)?;
        let mut der = self.base_der.clone();
        let len = der.len();
        der[len - 64..].copy_from_slice(&signature);
        Ok(der)
    }
}

// ---------------------------------------------------------------------------
// Minimal DER encoding
// ---------------------------------------------------------------------------

/// Ed25519 algorithm OID 1.3.101.112.
const OID_ED25519: [u8; 5] = [0x06, 0x03, 0x2b, 0x65, 0x70];
/// commonName attribute OID 2.5.4.3.
const OID_COMMON_NAME: [u8; 5] = [0x06, 0x03, 0x55, 0x04, 0x03];

/// Encodes a DER length.
fn der_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len < 0x100 {
        vec![0x81, len as u8]
    } else if len < 0x10000 {
        vec![0x82, (len >> 8) as u8, len as u8]
    } else {
        vec![0x83, (len >> 16) as u8, (len >> 8) as u8, len as u8]
    }
}

/// Encodes a DER TLV with the given tag wrapping `content`.
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 4);
    out.push(tag);
    out.extend_from_slice(&der_len(content.len()));
    out.extend_from_slice(content);
    out
}

/// Encodes a BIT STRING with zero unused bits.
fn bit_string(content: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(content.len() + 1);
    body.push(0x00);
    body.extend_from_slice(content);
    tlv(0x03, &body)
}

/// Builds the `Name` (single commonName RDN).
fn name() -> Vec<u8> {
    let mut atv = OID_COMMON_NAME.to_vec();
    atv.extend_from_slice(&tlv(0x0c, b"REALITY")); // UTF8String
    let atv = tlv(0x30, &atv); // AttributeTypeAndValue
    let rdn = tlv(0x31, &atv); // RelativeDistinguishedName (SET)
    tlv(0x30, &rdn) // RDNSequence (SEQUENCE)
}

/// Encodes a UTCTime (`YYMMDDHHMMSSZ`) for the given unix time.
fn utc_time(unix: u64) -> Vec<u8> {
    let (year, month, day, hour, min, sec) = civil_from_unix(unix);
    let text = format!(
        "{:02}{:02}{:02}{:02}{:02}{:02}Z",
        year % 100,
        month,
        day,
        hour,
        min,
        sec
    );
    tlv(0x17, text.as_bytes())
}

/// Converts unix seconds to `(year, month, day, hour, minute, second)` (UTC).
fn civil_from_unix(unix: u64) -> (i64, u32, u32, u32, u32, u32) {
    let days = (unix / 86_400) as i64;
    let secs_of_day = (unix % 86_400) as u32;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = year + if month <= 2 { 1 } else { 0 };
    (
        year,
        month,
        day,
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60,
    )
}

/// Builds the full self-issued certificate DER with a zeroed signature.
fn build_certificate(public_key: &[u8; 32], now: u64) -> io::Result<Vec<u8>> {
    // version [0] EXPLICIT INTEGER 2 (v3)
    let version = tlv(0xa0, &tlv(0x02, &[0x02]));

    // serialNumber: 16 random-ish bytes; force the high bit clear so it stays a
    // positive INTEGER without a leading 0x00 pad.
    let mut serial_bytes = [0u8; 16];
    serial_bytes.copy_from_slice(&public_key[..16]);
    serial_bytes[0] &= 0x7f;
    serial_bytes[0] |= 0x01;
    let serial = tlv(0x02, &serial_bytes);

    let alg_id = tlv(0x30, &OID_ED25519);

    let not_before = utc_time(now.saturating_sub(86_400));
    let not_after = utc_time(now + Duration::from_secs(365 * 86_400).as_secs());
    let mut validity_body = not_before;
    validity_body.extend_from_slice(&not_after);
    let validity = tlv(0x30, &validity_body);

    let issuer = name();
    let subject = name();

    // SubjectPublicKeyInfo
    let mut spki_body = alg_id.clone();
    spki_body.extend_from_slice(&bit_string(public_key));
    let spki = tlv(0x30, &spki_body);

    // TBSCertificate
    let mut tbs_body = Vec::new();
    tbs_body.extend_from_slice(&version);
    tbs_body.extend_from_slice(&serial);
    tbs_body.extend_from_slice(&alg_id);
    tbs_body.extend_from_slice(&issuer);
    tbs_body.extend_from_slice(&validity);
    tbs_body.extend_from_slice(&subject);
    tbs_body.extend_from_slice(&spki);
    let tbs = tlv(0x30, &tbs_body);

    // Certificate ::= SEQUENCE { tbs, sigAlg, signature(64 zero bytes) }
    let mut cert_body = tbs;
    cert_body.extend_from_slice(&alg_id);
    cert_body.extend_from_slice(&bit_string(&[0u8; 64]));
    Ok(tlv(0x30, &cert_body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use boring::x509::X509;

    #[test]
    fn builds_parseable_certificate() {
        let cert = RealityCertificate::generate().unwrap();
        // BoringSSL must accept the hand-built DER.
        let parsed = X509::from_der(&cert.base_der).unwrap();
        // The leaf public key round-trips back to our Ed25519 key.
        let pubkey = parsed.public_key().unwrap();
        let mut raw = [0u8; 32];
        pubkey.raw_public_key(&mut raw).unwrap();
        assert_eq!(&raw, &cert.public);
    }

    #[test]
    fn forges_signature_into_trailing_bytes() {
        let cert = RealityCertificate::generate().unwrap();
        let der = cert.forge(&[0x11; 32]).unwrap();
        let signature = certificate_signature(&[0x11; 32], &cert.public).unwrap();
        assert_eq!(&der[der.len() - 64..], &signature[..]);

        let other = cert.forge(&[0x22; 32]).unwrap();
        assert_ne!(&der[der.len() - 64..], &other[other.len() - 64..]);
        // Still valid DER after splicing.
        X509::from_der(&der).unwrap();
    }

    #[test]
    fn civil_time_matches_known_values() {
        // 2021-01-01T00:00:00Z == 1609459200
        assert_eq!(civil_from_unix(1_609_459_200), (2021, 1, 1, 0, 0, 0));
        // 2000-02-29T12:34:56Z == 951827696
        assert_eq!(civil_from_unix(951_827_696), (2000, 2, 29, 12, 34, 56));
    }
}
