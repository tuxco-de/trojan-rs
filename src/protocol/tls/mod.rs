use tokio_rustls::rustls::{
    crypto::ring::DEFAULT_CIPHER_SUITES, CipherSuite, SupportedCipherSuite,
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use rustls_pemfile::certs;

use crate::error::Error;
use std::{
    fs::File,
    io::{self, BufReader},
    path::Path,
};

pub mod acceptor;
pub mod connector;

fn new_error<T: ToString>(message: T) -> io::Error {
    Error::new(format!("tls: {}", message.to_string())).into()
}

pub fn load_cert(path: &Path) -> io::Result<Vec<CertificateDer<'static>>> {
    let mut reader = BufReader::new(File::open(path)?);
    let mut certs_vec = Vec::new();
    for cert in certs(&mut reader) {
        certs_vec.push(
            cert.map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid tls cert"))?
                .into_owned(),
        );
    }
    Ok(certs_vec)
}

pub fn load_key(path: &Path) -> io::Result<PrivateKeyDer<'static>> {
    let mut reader = BufReader::new(File::open(path)?);
    if let Some(key) = rustls_pemfile::private_key(&mut reader)? {
        return Ok(key);
    }
    Err(new_error("no valid key found"))
}

fn get_cipher_name(cipher: SupportedCipherSuite) -> &'static str {
    match cipher.suite() {
        CipherSuite::TLS13_CHACHA20_POLY1305_SHA256 => "TLS13_CHACHA20_POLY1305_SHA256",
        CipherSuite::TLS13_AES_256_GCM_SHA384 => "TLS13_AES_256_GCM_SHA384",
        CipherSuite::TLS13_AES_128_GCM_SHA256 => "TLS13_AES_128_GCM_SHA256",
        CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 => {
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
        }
        CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => {
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
        }
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 => {
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
        }
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 => {
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
        }
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => {
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
        }
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => {
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
        }
        _ => "???",
    }
}

pub fn get_cipher_suite(cipher: Option<Vec<String>>) -> io::Result<Vec<SupportedCipherSuite>> {
    if cipher.is_none() {
        return Ok(DEFAULT_CIPHER_SUITES.to_vec());
    }
    let cipher = cipher.unwrap();
    let mut result = Vec::new();

    for name in cipher {
        let mut found = false;
        for i in DEFAULT_CIPHER_SUITES.iter().copied() {
            if name == get_cipher_name(i) {
                result.push(i);
                found = true;
                log::debug!("cipher: {} applied", name);
                break;
            }
        }
        if !found {
            return Err(new_error(format!("bad cipher: {}", name)));
        }
    }
    Ok(result)
}
