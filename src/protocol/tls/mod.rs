use crate::error::Error;
use std::io;

pub mod acceptor;
pub mod connector;

fn new_error<T: ToString>(message: T) -> io::Error {
    Error::new(format!("tls: {}", message.to_string())).into()
}

pub fn get_cipher_list(cipher: Option<&[String]>) -> io::Result<Option<String>> {
    let Some(cipher) = cipher else {
        return Ok(None);
    };
    if cipher.is_empty() {
        return Err(new_error("cipher list cannot be empty"));
    }

    cipher
        .iter()
        .map(|name| {
            let openssl_name = match name.as_str() {
                "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256" => "ECDHE-ECDSA-CHACHA20-POLY1305",
                "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256" => "ECDHE-RSA-CHACHA20-POLY1305",
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" => "ECDHE-ECDSA-AES256-GCM-SHA384",
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" => "ECDHE-ECDSA-AES128-GCM-SHA256",
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" => "ECDHE-RSA-AES256-GCM-SHA384",
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" => "ECDHE-RSA-AES128-GCM-SHA256",
                name if name.starts_with("TLS13_") => {
                    return Err(new_error(
                        "BoringSSL does not expose TLS 1.3 cipher suite configuration",
                    ));
                }
                _ => return Err(new_error(format!("bad cipher: {name}"))),
            };
            Ok(openssl_name)
        })
        .collect::<io::Result<Vec<_>>>()
        .map(|names| Some(names.join(":")))
}

#[cfg(test)]
mod tests {
    use super::get_cipher_list;

    #[test]
    fn translates_tls12_cipher_names() {
        let ciphers = vec![
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256".to_owned(),
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256".to_owned(),
        ];
        assert_eq!(
            get_cipher_list(Some(&ciphers)).unwrap().as_deref(),
            Some("ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-CHACHA20-POLY1305")
        );
    }

    #[test]
    fn rejects_tls13_cipher_configuration() {
        let ciphers = vec!["TLS13_AES_128_GCM_SHA256".to_owned()];
        assert!(get_cipher_list(Some(&ciphers)).is_err());
    }
}
