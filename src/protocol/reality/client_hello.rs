//! Minimal TLS ClientHello parser for REALITY.
//!
//! This deliberately parses only the fields REALITY needs (SNI, `session_id`,
//! client random, and the X25519 key share) and validates every length before
//! indexing so malformed input can never panic.  It operates on the *handshake
//! message* bytes (`handshake_type || u24_length || body`), which is what gets
//! authenticated as the AES-GCM AAD.

use super::new_error;
use std::io;

/// `handshake(22)` TLS record content type.
pub const RECORD_TYPE_HANDSHAKE: u8 = 0x16;
/// `client_hello(1)` handshake message type.
pub const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;

const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const EXT_KEY_SHARE: u16 = 0x0033;

const GROUP_X25519: u16 = 0x001d;
const GROUP_X25519MLKEM768: u16 = 0x11ec;
/// X25519 public key length, also the trailing portion of an X25519MLKEM768 share.
const X25519_KEY_LEN: usize = 32;
/// ML-KEM-768 encapsulation key length that precedes the X25519 key in a hybrid share.
const MLKEM768_ENCAP_LEN: usize = 1184;

const TLS13_VERSION: u16 = 0x0304;

/// Parsed REALITY-relevant fields of a ClientHello.
#[derive(Debug)]
pub struct ParsedClientHello {
    /// 32-byte client random.
    pub random: [u8; 32],
    /// Server Name Indication, lowercased; empty when absent.
    pub server_name: String,
    /// X25519 key share public key, when offered (plain or hybrid).
    pub key_share_x25519: Option<[u8; 32]>,
    /// Whether the client advertised TLS 1.3 via supported_versions.
    pub offers_tls13: bool,
    /// Byte offset of the `session_id` value within the handshake message.
    pub session_id_offset: usize,
    /// The 32-byte `session_id` value (REALITY requires exactly 32).
    pub session_id: [u8; 32],
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    fn take(&mut self, len: usize) -> io::Result<&'a [u8]> {
        if self.remaining() < len {
            return Err(new_error("ClientHello truncated"));
        }
        let slice = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Ok(slice)
    }

    fn u8(&mut self) -> io::Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> io::Result<u16> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }
}

/// Parses a ClientHello handshake message (`type || u24_len || body`).
pub fn parse(message: &[u8]) -> io::Result<ParsedClientHello> {
    let mut reader = Reader::new(message);
    if reader.u8()? != HANDSHAKE_TYPE_CLIENT_HELLO {
        return Err(new_error("not a ClientHello handshake message"));
    }
    let body_len = {
        let bytes = reader.take(3)?;
        ((bytes[0] as usize) << 16) | ((bytes[1] as usize) << 8) | bytes[2] as usize
    };
    if reader.remaining() != body_len {
        return Err(new_error("ClientHello length mismatch"));
    }

    // legacy_version
    reader.u16()?;

    let mut random = [0u8; 32];
    random.copy_from_slice(reader.take(32)?);

    let session_id_len = reader.u8()? as usize;
    let session_id_offset = reader.pos;
    let session_id_bytes = reader.take(session_id_len)?;
    let mut session_id = [0u8; 32];
    if session_id_len == 32 {
        session_id.copy_from_slice(session_id_bytes);
    }

    // cipher_suites
    let cipher_len = reader.u16()? as usize;
    reader.take(cipher_len)?;

    // compression_methods
    let compression_len = reader.u8()? as usize;
    reader.take(compression_len)?;

    let mut server_name = String::new();
    let mut key_share_x25519 = None;
    let mut offers_tls13 = false;

    if reader.remaining() > 0 {
        let extensions_len = reader.u16()? as usize;
        if reader.remaining() != extensions_len {
            return Err(new_error("ClientHello extensions length mismatch"));
        }
        while reader.remaining() > 0 {
            let ext_type = reader.u16()?;
            let ext_len = reader.u16()? as usize;
            let ext_data = reader.take(ext_len)?;
            match ext_type {
                EXT_SERVER_NAME => {
                    if let Some(name) = parse_sni(ext_data) {
                        server_name = name;
                    }
                }
                EXT_SUPPORTED_VERSIONS => {
                    offers_tls13 = parse_supported_versions(ext_data);
                }
                EXT_KEY_SHARE => {
                    key_share_x25519 = parse_key_share(ext_data);
                }
                _ => {}
            }
        }
    }

    Ok(ParsedClientHello {
        random,
        server_name,
        key_share_x25519,
        offers_tls13,
        session_id_offset,
        session_id,
    })
}

fn parse_sni(ext_data: &[u8]) -> Option<String> {
    let mut reader = Reader::new(ext_data);
    let list_len = reader.u16().ok()? as usize;
    if reader.remaining() != list_len {
        return None;
    }
    while reader.remaining() > 0 {
        let name_type = reader.u8().ok()?;
        let name_len = reader.u16().ok()? as usize;
        let name = reader.take(name_len).ok()?;
        if name_type == 0 {
            return std::str::from_utf8(name)
                .ok()
                .map(|name| name.to_ascii_lowercase());
        }
    }
    None
}

fn parse_supported_versions(ext_data: &[u8]) -> bool {
    let mut reader = Reader::new(ext_data);
    let Ok(list_len) = reader.u8() else {
        return false;
    };
    if reader.remaining() != list_len as usize {
        return false;
    }
    while reader.remaining() >= 2 {
        if reader.u16().ok() == Some(TLS13_VERSION) {
            return true;
        }
    }
    false
}

fn parse_key_share(ext_data: &[u8]) -> Option<[u8; 32]> {
    let mut reader = Reader::new(ext_data);
    let shares_len = reader.u16().ok()? as usize;
    if reader.remaining() != shares_len {
        return None;
    }
    while reader.remaining() > 0 {
        let group = reader.u16().ok()?;
        let key_len = reader.u16().ok()? as usize;
        let key = reader.take(key_len).ok()?;
        match group {
            GROUP_X25519 if key_len == X25519_KEY_LEN => {
                let mut out = [0u8; 32];
                out.copy_from_slice(key);
                return Some(out);
            }
            GROUP_X25519MLKEM768 if key_len == MLKEM768_ENCAP_LEN + X25519_KEY_LEN => {
                let mut out = [0u8; 32];
                out.copy_from_slice(&key[MLKEM768_ENCAP_LEN..]);
                return Some(out);
            }
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_client_hello() -> Vec<u8> {
        // Build a minimal but well-formed TLS 1.3 ClientHello body.
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // legacy_version TLS 1.2
        body.extend_from_slice(&[0xAA; 32]); // random
        body.push(32); // session_id length
        body.extend_from_slice(&[0xBB; 32]); // session_id (REALITY ciphertext)
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher_suites
        body.extend_from_slice(&[0x01, 0x00]); // compression_methods

        let mut extensions = Vec::new();
        // SNI: example.com
        let host = b"example.com";
        let mut sni = Vec::new();
        sni.push(0x00); // name type host_name
        sni.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sni.extend_from_slice(host);
        let mut sni_ext = Vec::new();
        sni_ext.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(&sni);
        extensions.extend_from_slice(&EXT_SERVER_NAME.to_be_bytes());
        extensions.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sni_ext);
        // supported_versions: TLS 1.3
        extensions.extend_from_slice(&EXT_SUPPORTED_VERSIONS.to_be_bytes());
        extensions.extend_from_slice(&[0x00, 0x03, 0x02, 0x03, 0x04]);
        // key_share: X25519
        let mut shares = Vec::new();
        shares.extend_from_slice(&GROUP_X25519.to_be_bytes());
        shares.extend_from_slice(&(32u16).to_be_bytes());
        shares.extend_from_slice(&[0xCC; 32]);
        let mut ks_ext = Vec::new();
        ks_ext.extend_from_slice(&(shares.len() as u16).to_be_bytes());
        ks_ext.extend_from_slice(&shares);
        extensions.extend_from_slice(&EXT_KEY_SHARE.to_be_bytes());
        extensions.extend_from_slice(&(ks_ext.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&ks_ext);

        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut message = Vec::new();
        message.push(HANDSHAKE_TYPE_CLIENT_HELLO);
        let len = body.len();
        message.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
        message.extend_from_slice(&body);
        message
    }

    #[test]
    fn parses_reality_fields() {
        let message = sample_client_hello();
        let parsed = parse(&message).unwrap();
        assert_eq!(parsed.server_name, "example.com");
        assert_eq!(parsed.random, [0xAA; 32]);
        assert_eq!(parsed.session_id, [0xBB; 32]);
        assert_eq!(parsed.key_share_x25519, Some([0xCC; 32]));
        assert!(parsed.offers_tls13);
        // session_id sits at: 1(type)+3(len)+2(version)+32(random)+1(sid len)
        assert_eq!(parsed.session_id_offset, 39);
        assert_eq!(
            &message[parsed.session_id_offset..parsed.session_id_offset + 32],
            &[0xBB; 32]
        );
    }

    #[test]
    fn rejects_malformed_input() {
        assert!(parse(&[]).is_err());
        assert!(parse(&[HANDSHAKE_TYPE_CLIENT_HELLO, 0x00, 0x00, 0xff]).is_err());
        // Truncated body
        let mut message = sample_client_hello();
        message.truncate(message.len() - 10);
        assert!(parse(&message).is_err());
    }
}
