use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use p384::ecdsa::{Signature as Signature384, SigningKey as SigningKey384};
use rand::rngs::OsRng;
use rsa::signature::SignatureEncoding;
use rsa::{RsaPrivateKey, pkcs1::DecodeRsaPrivateKey, traits::PublicKeyParts};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{fs, path::Path};
use x509_parser::{
    certification_request::X509CertificationRequest,
    extensions::{GeneralName, ParsedExtension},
    prelude::FromDer,
};

pub fn init_tls() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

#[derive(Clone)]
pub enum AccountKey {
    Ec(SigningKey),
    Ec384(SigningKey384),
    Rsa(Box<RsaPrivateKey>),
}

impl AccountKey {
    pub fn generate_with_curve(ec: bool, bits: usize, ec384: bool) -> Result<Self> {
        if ec {
            if ec384 {
                Ok(Self::Ec384(SigningKey384::random(&mut OsRng)))
            } else {
                Ok(Self::Ec(SigningKey::random(&mut OsRng)))
            }
        } else {
            Ok(Self::Rsa(Box::new(RsaPrivateKey::new(&mut OsRng, bits)?)))
        }
    }
    pub fn load(path: &Path) -> Result<Self> {
        let pem =
            fs::read_to_string(path).with_context(|| format!("read key {}", path.display()))?;
        if (pem.contains("EC PRIVATE KEY")
            || pem.contains("PRIVATE KEY") && !pem.contains("RSA PRIVATE KEY"))
            && let Ok(k) = SigningKey::from_pkcs8_pem(&pem)
        {
            return Ok(Self::Ec(k));
        }
        if let Ok(k) = SigningKey384::from_pkcs8_pem(&pem) {
            return Ok(Self::Ec384(k));
        }
        let rsa =
            RsaPrivateKey::from_pkcs8_pem(&pem).or_else(|_| RsaPrivateKey::from_pkcs1_pem(&pem))?;
        Ok(Self::Rsa(Box::new(rsa)))
    }
    pub fn pem(&self) -> Result<String> {
        Ok(match self {
            Self::Ec(k) => k.to_pkcs8_pem(Default::default())?.to_string(),
            Self::Ec384(k) => k.to_pkcs8_pem(Default::default())?.to_string(),
            Self::Rsa(k) => k.to_pkcs8_pem(Default::default())?.to_string(),
        })
    }
    pub fn alg(&self) -> &'static str {
        match self {
            Self::Ec(_) => "ES256",
            Self::Ec384(_) => "ES384",
            Self::Rsa(_) => "RS256",
        }
    }
    pub fn jwk(&self) -> Value {
        match self {
            Self::Ec(k) => {
                let p = k.verifying_key().to_encoded_point(false);
                json!({"kty":"EC","crv":"P-256","x":URL_SAFE_NO_PAD.encode(&p.as_bytes()[1..33]),"y":URL_SAFE_NO_PAD.encode(&p.as_bytes()[33..65])})
            }
            Self::Ec384(k) => {
                let p = k.verifying_key().to_encoded_point(false);
                json!({"kty":"EC","crv":"P-384","x":URL_SAFE_NO_PAD.encode(&p.as_bytes()[1..49]),"y":URL_SAFE_NO_PAD.encode(&p.as_bytes()[49..97])})
            }
            Self::Rsa(k) => {
                json!({"kty":"RSA","n":URL_SAFE_NO_PAD.encode(unsigned(&k.n().to_bytes_be())),"e":URL_SAFE_NO_PAD.encode(unsigned(&k.e().to_bytes_be()))})
            }
        }
    }
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::Ec(k) => {
                let s: Signature = k.sign(data);
                Ok(s.to_bytes().to_vec())
            }
            Self::Ec384(k) => {
                let s: Signature384 = k.sign(data);
                Ok(s.to_bytes().to_vec())
            }
            Self::Rsa(k) => {
                use rsa::pkcs1v15::SigningKey as RsaSigningKey;
                let s = RsaSigningKey::<Sha256>::new((**k).clone()).sign(data);
                Ok(s.to_vec())
            }
        }
    }
}
fn unsigned(v: &[u8]) -> &[u8] {
    v.iter()
        .position(|x| *x != 0)
        .map(|i| &v[i..])
        .unwrap_or(&[0])
}
pub fn create_account_key(path: &Path, ec: bool, length: Option<&str>) -> Result<()> {
    let bits = length.and_then(|s| s.parse().ok()).unwrap_or(2048);
    let ec384 = length.is_some_and(|s| s.eq_ignore_ascii_case("ec-384"));
    let k = AccountKey::generate_with_curve(
        ec || length.is_some_and(|s| s.starts_with("ec")),
        bits,
        ec384,
    )?;
    write_private(path, &k.pem()?)
}
pub fn create_domain_key(path: &Path, ec: bool, length: Option<&str>) -> Result<()> {
    let bits = length.and_then(|s| s.parse().ok()).unwrap_or(2048);
    let ec384 = length.is_some_and(|s| s.eq_ignore_ascii_case("ec-384"));
    let k = AccountKey::generate_with_curve(
        ec || length.is_some_and(|s| s.starts_with("ec")),
        bits,
        ec384,
    )?;
    write_private(path, &k.pem()?)
}
fn write_private(path: &Path, text: &str) -> Result<()> {
    if let Some(p) = path.parent() {
        fs::create_dir_all(p)?;
    }
    fs::write(path, text)?;
    Ok(())
}
pub fn dns01_value(token: &str, account_thumbprint: &str) -> String {
    let mut h = Sha256::new();
    h.update(format!("{token}.{account_thumbprint}"));
    URL_SAFE_NO_PAD.encode(h.finalize())
}
pub fn thumbprint(key: &AccountKey) -> String {
    let jwk = key.jwk();
    let canonical = match jwk["kty"].as_str() {
        Some("EC") => json!({"crv":jwk["crv"],"kty":"EC","x":jwk["x"],"y":jwk["y"]}),
        Some("RSA") => json!({"e":jwk["e"],"kty":"RSA","n":jwk["n"]}),
        _ => jwk,
    };
    let mut h = Sha256::new();
    h.update(serde_json::to_vec(&canonical).unwrap());
    URL_SAFE_NO_PAD.encode(h.finalize())
}
pub fn create_csr(domain_key: &Path, domains: &[String], output: &Path) -> Result<()> {
    let kp = rcgen::KeyPair::from_pem(&fs::read_to_string(domain_key)?)?;
    let mut params = rcgen::CertificateParams::new(domains.to_vec())?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, domains[0].clone());
    let csr = params.serialize_request(&kp)?;
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(output, csr.pem()?)?;
    Ok(())
}
pub fn show_csr(path: &Path) -> Result<String> {
    let der = pem::parse(fs::read(path)?)?.contents().to_vec();
    let (_, csr) = X509CertificationRequest::from_der(&der)
        .map_err(|error| anyhow::anyhow!("invalid CSR: {error}"))?;
    let sans = csr
        .requested_extensions()
        .into_iter()
        .flatten()
        .filter_map(|extension| match extension {
            ParsedExtension::SubjectAlternativeName(names) => Some(
                names
                    .general_names
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>(),
            ),
            _ => None,
        })
        .flatten()
        .collect::<Vec<_>>()
        .join(",");
    Ok(format!(
        "subject: {}\nsignature_algorithm: {}\nsans: {}",
        csr.certification_request_info.subject, csr.signature_algorithm.algorithm, sans
    ))
}
pub fn csr_domains(path: &Path) -> Result<Vec<String>> {
    let der = pem::parse(fs::read(path)?)?.contents().to_vec();
    let (_, csr) = X509CertificationRequest::from_der(&der)
        .map_err(|error| anyhow::anyhow!("invalid CSR: {error}"))?;
    let mut domains = csr
        .requested_extensions()
        .into_iter()
        .flatten()
        .filter_map(|extension| match extension {
            ParsedExtension::SubjectAlternativeName(names) => Some(
                names
                    .general_names
                    .iter()
                    .filter_map(|name| match name {
                        GeneralName::DNSName(value) => Some(value.to_ascii_lowercase()),
                        _ => None,
                    })
                    .collect::<Vec<_>>(),
            ),
            _ => None,
        })
        .flatten()
        .collect::<Vec<_>>();
    if domains.is_empty()
        && let Some(common_name) = csr
            .certification_request_info
            .subject
            .iter_common_name()
            .next()
            .and_then(|name| name.as_str().ok())
    {
        domains.push(common_name.to_ascii_lowercase());
    }
    domains.sort();
    domains.dedup();
    if domains.is_empty() {
        anyhow::bail!("CSR does not contain a DNS subject or SAN")
    }
    Ok(domains)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dns01_is_rfc4648_urlsafe() {
        assert_eq!(
            dns01_value("foo", "bar"),
            "JZXQitIscz96HOcT52dWPhOo36NbqnSRnCjg9YbLQks"
        );
    }
    #[test]
    fn ec_key_has_acme_jwk() {
        let k = AccountKey::generate_with_curve(true, 2048, false).unwrap();
        assert_eq!(k.jwk()["kty"], "EC");
        assert_eq!(k.alg(), "ES256");
    }
    #[test]
    fn p384_key_uses_es384_jwk() {
        let k = AccountKey::generate_with_curve(true, 2048, true).unwrap();
        assert_eq!(k.jwk()["crv"], "P-384");
        assert_eq!(k.alg(), "ES384");
        assert_eq!(k.sign(b"message").unwrap().len(), 96);
    }
    #[test]
    fn displays_csr_subject_and_sans() {
        let root = std::env::temp_dir().join(format!("rust-acmesh-csr-{}", uuid::Uuid::new_v4()));
        let key = root.join("domain.key");
        let csr = root.join("domain.csr");
        create_domain_key(&key, true, Some("ec-256")).unwrap();
        create_csr(
            &key,
            &["example.com".into(), "www.example.com".into()],
            &csr,
        )
        .unwrap();
        let text = show_csr(&csr).unwrap();
        assert!(text.contains("CN=example.com"));
        assert!(text.contains("example.com"));
        assert!(text.contains("www.example.com"));
    }
    #[test]
    fn extracts_domains_from_csr() {
        let root =
            std::env::temp_dir().join(format!("rust-acmesh-csr-domains-{}", uuid::Uuid::new_v4()));
        let key = root.join("domain.key");
        let csr = root.join("domain.csr");
        create_domain_key(&key, true, Some("ec-256")).unwrap();
        create_csr(
            &key,
            &["example.com".into(), "www.example.com".into()],
            &csr,
        )
        .unwrap();
        assert_eq!(
            csr_domains(&csr).unwrap(),
            vec!["example.com", "www.example.com"]
        );
    }
}
