//! REALITY cryptographic primitives.
//!
//! The server reproduces the same authentication material the client embeds in
//! the TLS ClientHello `session_id`.  The wire format and algorithm choices here
//! must match Xray-core's `transport/internet/reality/reality.go` and
//! `XTLS/REALITY` byte for byte, otherwise authentication silently fails and the
//! connection is forwarded to the decoy `target`.
//!
//! Algorithm summary (server side):
//!   * `shared   = X25519(server_private_key, client_key_share_pub)`
//!   * `auth_key = HKDF-SHA256(ikm = shared, salt = client_random[..20], info = "REALITY")`
//!   * `plain    = AES-256-GCM.open(key = auth_key, nonce = client_random[20..32],
//!                                  ct = session_id, aad = client_hello_with_session_id_zeroed)`
//!
//! `plain` is 16 bytes: `[ver(3), 0, unix_time_be(4), short_id(8)]`.

use boring::hash::{hmac_sha256, hmac_sha512};
use boring::symm::{decrypt_aead, Cipher};
use x25519_dalek::{PublicKey, StaticSecret};

use super::new_error;
use std::io;

/// HKDF `info` string used by REALITY.
const HKDF_INFO: &[u8] = b"REALITY";
/// Length of the X25519 shared secret / derived auth key.
pub const AUTH_KEY_LEN: usize = 32;
/// Length of the REALITY `session_id` (16 bytes ciphertext + 16 bytes GCM tag).
pub const SESSION_ID_LEN: usize = 32;
/// Length of the decrypted REALITY payload.
pub const PLAINTEXT_LEN: usize = 16;

/// Decodes a base64 (standard or URL-safe, padded or not) string into bytes.
///
/// REALITY private/public keys produced by `xray x25519` use RawURLEncoding, but
/// this decoder also tolerates the standard alphabet and padding so operators do
/// not get tripped up by a stray `+`/`/` or `=`.
pub fn base64_decode(input: &str) -> io::Result<Vec<u8>> {
    fn value(byte: u8) -> Option<u8> {
        match byte {
            b'A'..=b'Z' => Some(byte - b'A'),
            b'a'..=b'z' => Some(byte - b'a' + 26),
            b'0'..=b'9' => Some(byte - b'0' + 52),
            b'+' | b'-' => Some(62),
            b'/' | b'_' => Some(63),
            _ => None,
        }
    }

    let mut out = Vec::with_capacity(input.len() / 4 * 3 + 3);
    let mut acc = 0u32;
    let mut bits = 0u32;
    for &byte in input.as_bytes() {
        if byte == b'=' {
            break;
        }
        let Some(v) = value(byte) else {
            return Err(new_error("invalid base64 character in key"));
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Ok(out)
}

/// Parses a REALITY X25519 private key (32 raw bytes, base64-encoded).
pub fn parse_private_key(encoded: &str) -> io::Result<[u8; 32]> {
    let bytes = base64_decode(encoded.trim())?;
    if bytes.len() != 32 {
        return Err(new_error(format!(
            "private_key must decode to 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

/// Parses a REALITY short ID.
///
/// Short IDs are hex strings of even length, at most 16 hex characters (8 bytes).
/// They are stored left-aligned and zero-padded on the right, matching how the
/// client copies `ShortId` into `session_id[8..]`.  The empty string is valid and
/// maps to all-zero bytes.
pub fn parse_short_id(short_id: &str) -> io::Result<[u8; 8]> {
    let short_id = short_id.trim();
    if short_id.len() > 16 {
        return Err(new_error("short_id must be at most 16 hex characters"));
    }
    if !short_id.len().is_multiple_of(2) {
        return Err(new_error(
            "short_id must have an even number of hex characters",
        ));
    }
    let mut out = [0u8; 8];
    let bytes = short_id.as_bytes();
    for (index, pair) in bytes.chunks(2).enumerate() {
        let hi = hex_value(pair[0])?;
        let lo = hex_value(pair[1])?;
        out[index] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_value(byte: u8) -> io::Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(new_error("short_id must be hexadecimal")),
    }
}

/// Derives the REALITY auth key from the server private key, the client key share
/// public key, and the first 20 bytes of the client random.
pub fn derive_auth_key(
    private_key: &[u8; 32],
    peer_public: &[u8; 32],
    client_random_salt: &[u8],
) -> io::Result<[u8; AUTH_KEY_LEN]> {
    let secret = StaticSecret::from(*private_key);
    let public = PublicKey::from(*peer_public);
    let shared = secret.diffie_hellman(&public);

    // HKDF-SHA256 with L == hash length, so a single expand block suffices.
    let prk = hmac_sha256(client_random_salt, shared.as_bytes()).map_err(new_error)?;
    let mut info_block = Vec::with_capacity(HKDF_INFO.len() + 1);
    info_block.extend_from_slice(HKDF_INFO);
    info_block.push(0x01);
    let okm = hmac_sha256(&prk, &info_block).map_err(new_error)?;
    Ok(okm)
}

/// Decrypts the REALITY `session_id` and returns the 16-byte plaintext.
///
/// * `auth_key` — derived via [`derive_auth_key`].
/// * `nonce` — `client_random[20..32]` (12 bytes).
/// * `session_id` — the 32-byte ClientHello `session_id` (16 ciphertext + 16 tag).
/// * `aad` — the ClientHello handshake message with the `session_id` region
///   overwritten with zeros (REALITY's `clientHello.original`).
pub fn open_session_id(
    auth_key: &[u8; AUTH_KEY_LEN],
    nonce: &[u8],
    session_id: &[u8],
    aad: &[u8],
) -> io::Result<[u8; PLAINTEXT_LEN]> {
    if session_id.len() != SESSION_ID_LEN {
        return Err(new_error("session_id must be 32 bytes"));
    }
    let (ciphertext, tag) = session_id.split_at(16);
    let plain = decrypt_aead(
        Cipher::aes_256_gcm(),
        auth_key,
        Some(nonce),
        aad,
        ciphertext,
        tag,
    )
    .map_err(|_| new_error("REALITY authentication tag mismatch"))?;
    if plain.len() != PLAINTEXT_LEN {
        return Err(new_error("unexpected REALITY plaintext length"));
    }
    let mut out = [0u8; PLAINTEXT_LEN];
    out.copy_from_slice(&plain);
    Ok(out)
}

/// Splits the decrypted REALITY plaintext into its fields.
///
/// Returns `(client_version, unix_time_secs, short_id)`.
pub fn parse_plaintext(plain: &[u8; PLAINTEXT_LEN]) -> ([u8; 3], u32, [u8; 8]) {
    let mut version = [0u8; 3];
    version.copy_from_slice(&plain[0..3]);
    let time = u32::from_be_bytes([plain[4], plain[5], plain[6], plain[7]]);
    let mut short_id = [0u8; 8];
    short_id.copy_from_slice(&plain[8..16]);
    (version, time, short_id)
}

/// Computes the forged leaf-certificate signature: `HMAC-SHA512(auth_key, ed25519_pub)`.
pub fn certificate_signature(
    auth_key: &[u8; AUTH_KEY_LEN],
    ed25519_public: &[u8; 32],
) -> io::Result<[u8; 64]> {
    hmac_sha512(auth_key, ed25519_public).map_err(new_error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_base64_url_and_standard() {
        // 32 zero bytes, RawURLEncoding == 43 'A' characters.
        let key = parse_private_key(&"A".repeat(43)).unwrap();
        assert_eq!(key, [0u8; 32]);
        // Standard alphabet with padding decodes to the same bytes.
        assert_eq!(base64_decode("AAAA").unwrap(), vec![0, 0, 0]);
        assert!(parse_private_key("####").is_err());
        assert!(parse_private_key("AAAA").is_err());
    }

    #[test]
    fn parses_short_ids() {
        assert_eq!(parse_short_id("").unwrap(), [0u8; 8]);
        assert_eq!(
            parse_short_id("0123456789abcdef").unwrap(),
            [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]
        );
        assert_eq!(parse_short_id("01").unwrap(), [0x01, 0, 0, 0, 0, 0, 0, 0]);
        assert!(parse_short_id("0").is_err());
        assert!(parse_short_id("zz").is_err());
        assert!(parse_short_id("00112233445566778899").is_err());
    }

    #[test]
    fn parses_plaintext_fields() {
        let mut plain = [0u8; PLAINTEXT_LEN];
        plain[0..3].copy_from_slice(&[1, 2, 3]);
        plain[4..8].copy_from_slice(&0x6500_0000u32.to_be_bytes());
        plain[8..16].copy_from_slice(&[9, 9, 9, 9, 9, 9, 9, 9]);
        let (ver, time, short_id) = parse_plaintext(&plain);
        assert_eq!(ver, [1, 2, 3]);
        assert_eq!(time, 0x6500_0000);
        assert_eq!(short_id, [9u8; 8]);
    }

    #[test]
    fn auth_key_and_session_id_round_trip() {
        // Derive an auth key, encrypt a known plaintext exactly like the client,
        // then confirm the server decrypt path recovers it.
        use boring::symm::encrypt_aead;

        let server_secret = StaticSecret::from([7u8; 32]);
        let server_public = PublicKey::from(&server_secret);
        let client_secret = StaticSecret::from([9u8; 32]);
        let client_public = PublicKey::from(&client_secret);

        let mut random = [0u8; 32];
        for (i, b) in random.iter_mut().enumerate() {
            *b = i as u8;
        }

        // `derive_auth_key` clamps the scalar internally, matching curve25519.X25519.
        let server_private = [7u8; 32];
        let auth_key =
            derive_auth_key(&server_private, client_public.as_bytes(), &random[..20]).unwrap();

        // Client-equivalent derivation using the server public key.
        let client_auth = {
            let shared = client_secret.diffie_hellman(&server_public);
            let prk = hmac_sha256(&random[..20], shared.as_bytes()).unwrap();
            let mut info = HKDF_INFO.to_vec();
            info.push(1);
            hmac_sha256(&prk, &info).unwrap()
        };
        assert_eq!(auth_key, client_auth);

        let aad = b"fake-client-hello-with-zeroed-session-id";
        let mut plain = [0u8; PLAINTEXT_LEN];
        plain[8..16].copy_from_slice(&[0xab; 8]);
        let mut tag = [0u8; 16];
        let ciphertext = encrypt_aead(
            Cipher::aes_256_gcm(),
            &auth_key,
            Some(&random[20..32]),
            aad,
            &plain,
            &mut tag,
        )
        .unwrap();
        let mut session_id = Vec::new();
        session_id.extend_from_slice(&ciphertext);
        session_id.extend_from_slice(&tag);

        let recovered = open_session_id(&auth_key, &random[20..32], &session_id, aad).unwrap();
        assert_eq!(recovered, plain);

        // Wrong AAD must fail authentication.
        assert!(open_session_id(&auth_key, &random[20..32], &session_id, b"tampered").is_err());
    }
}
