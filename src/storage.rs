use crate::cli::Args;
use anyhow::{Context, Result, bail};
use std::{
    fs,
    path::{Path, PathBuf},
};
use x509_parser::prelude::{FromDer, X509Certificate};

pub struct Store {
    pub home: PathBuf,
    pub config_home: PathBuf,
    pub cert_home: PathBuf,
    account_conf_override: Option<PathBuf>,
    domain_conf_override: Option<PathBuf>,
}
impl Store {
    pub fn new(
        home: Option<PathBuf>,
        config_home: Option<PathBuf>,
        cert_home: Option<PathBuf>,
        account_conf: Option<PathBuf>,
        domain_conf: Option<PathBuf>,
    ) -> Result<Self> {
        let home = home
            .or_else(|| {
                std::env::var_os("HOME")
                    .map(PathBuf::from)
                    .map(|p| p.join(".acme.sh"))
            })
            .unwrap_or_else(|| dirs_fallback().join(".acme.sh"));
        let config_home = config_home.unwrap_or_else(|| home.clone());
        let cert_home = cert_home.unwrap_or_else(|| home.clone());
        fs::create_dir_all(&home)?;
        fs::create_dir_all(&config_home)?;
        fs::create_dir_all(&cert_home)?;
        Ok(Self {
            home,
            config_home,
            cert_home,
            account_conf_override: account_conf,
            domain_conf_override: domain_conf,
        })
    }
    pub fn domain_dir(&self, domain: &str) -> PathBuf {
        self.cert_home
            .join(domain.replace("*.", "wildcard_").replace(':', "_"))
    }
    pub fn account_key(&self) -> PathBuf {
        self.home.join("account.key")
    }
    pub fn account_conf(&self) -> PathBuf {
        self.account_conf_override
            .clone()
            .unwrap_or_else(|| self.config_home.join("account.conf"))
    }
    pub fn domain_conf(&self, domain: &str) -> PathBuf {
        self.domain_conf_override.clone().unwrap_or_else(|| {
            self.domain_dir(domain)
                .join(format!("{}.conf", domain.replace("*.", "wildcard_")))
        })
    }
}
fn dirs_fallback() -> PathBuf {
    std::env::var_os("USERPROFILE")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("."))
}
pub fn install_cert(args: &Args, store: &Store) -> Result<()> {
    let d = args.domains.first().context("-d/--domain is required")?;
    let dir = store.domain_dir(d);
    let pairs = [
        (args.cert_file.as_ref(), "cert.cer"),
        (args.key_file.as_ref(), "key.pem"),
        (args.ca_file.as_ref(), "ca.cer"),
        (args.fullchain_file.as_ref(), "fullchain.cer"),
    ];
    for (to, name) in pairs {
        if let Some(to) = to {
            atomic_copy(&dir.join(name), to)?;
        }
    }
    println!("certificate installed for {d}");
    Ok(())
}
fn atomic_copy(from: &Path, to: &Path) -> Result<()> {
    if !from.exists() {
        bail!("missing {}", from.display());
    }
    if let Some(p) = to.parent() {
        fs::create_dir_all(p)?;
    }
    let tmp = to.with_extension("tmp");
    fs::copy(from, &tmp)?;
    fs::rename(tmp, to)?;
    Ok(())
}
pub fn list(store: &Store) -> Result<()> {
    println!("Domain\tSerial\tNotAfter");
    for e in fs::read_dir(&store.cert_home)? {
        let e = e?;
        let cert = e.path().join("cert.cer");
        if e.file_type()?.is_dir() && cert.exists() {
            match parse_certificate(&cert) {
                Ok(parsed) => println!(
                    "{}\t{}\t{}",
                    e.file_name().to_string_lossy(),
                    parsed.serial,
                    parsed.not_after
                ),
                Err(_) => println!("{}\tinvalid\tinvalid", e.file_name().to_string_lossy()),
            }
        }
    }
    Ok(())
}
pub fn info(args: &Args, store: &Store) -> Result<()> {
    let d = args.domains.first().context("-d/--domain is required")?;
    let p = store.domain_dir(d);
    let cert_path = p.join("cert.cer");
    if !cert_path.is_file() {
        bail!("certificate not found for {d}");
    }
    let parsed = parse_certificate(&cert_path)?;
    println!(
        "domain: {d}\npath: {}\nsubject: {}\nissuer: {}\nserial: {}\nnot_before: {}\nnot_after: {}\nsans: {}",
        p.display(),
        parsed.subject,
        parsed.issuer,
        parsed.serial,
        parsed.not_before,
        parsed.not_after,
        parsed.sans
    );
    Ok(())
}

struct CertificateInfo {
    subject: String,
    issuer: String,
    serial: String,
    not_before: String,
    not_after: String,
    sans: String,
}
fn parse_certificate(path: &Path) -> Result<CertificateInfo> {
    let der = pem::parse(fs::read(path)?)?.contents().to_vec();
    let (_, cert) = X509Certificate::from_der(&der)
        .map_err(|error| anyhow::anyhow!("invalid certificate: {error}"))?;
    let sans = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|extension| {
            extension
                .value
                .general_names
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",")
        })
        .unwrap_or_default();
    Ok(CertificateInfo {
        subject: cert.subject().to_string(),
        issuer: cert.issuer().to_string(),
        serial: cert.raw_serial_as_string(),
        not_before: cert.validity().not_before.to_string(),
        not_after: cert.validity().not_after.to_string(),
        sans,
    })
}
pub fn remove(args: &Args, store: &Store) -> Result<()> {
    let d = args.domains.first().context("-d/--domain is required")?;
    let p = store.domain_dir(d);
    if p.exists() {
        fs::remove_dir_all(p)?;
    }
    println!("removed {d}");
    Ok(())
}

#[cfg(feature = "pkcs12")]
pub fn to_pkcs12(args: &Args, store: &Store) -> Result<()> {
    let domain = args.domains.first().context("-d/--domain is required")?;
    let dir = store.domain_dir(domain);
    let certificate = fs::read(dir.join("cert.cer"))?;
    let key = fs::read(dir.join("key.pem"))?;
    let ca = fs::read(dir.join("ca.cer")).unwrap_or_default();
    let password = args.password.as_deref().unwrap_or("");
    let archive = pkcs12_bytes(&certificate, &key, &ca, password, domain)?;
    let output = args
        .cert_file
        .clone()
        .unwrap_or_else(|| dir.join(format!("{domain}.pfx")));
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&output, archive)?;
    println!("saved {}", output.display());
    Ok(())
}

pub fn to_pkcs8(args: &Args, store: &Store) -> Result<()> {
    let (input, output) = if let Some(path) = &args.key_file {
        (path.clone(), path.with_extension("pkcs8.pem"))
    } else {
        let domain = args
            .domains
            .first()
            .context("-d/--domain or --key-file is required")?;
        let dir = store.domain_dir(domain);
        (dir.join("key.pem"), dir.join("domain.pkcs8"))
    };
    let key = crate::crypto::AccountKey::load(&input)?;
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&output, key.pem()?)?;
    println!("saved {}", output.display());
    Ok(())
}

#[cfg(feature = "pkcs12")]
fn pkcs12_bytes(
    certificate_pem: &[u8],
    key_pem: &[u8],
    ca_pem: &[u8],
    password: &str,
    name: &str,
) -> Result<Vec<u8>> {
    let certificate = pem::parse(certificate_pem)?.contents().to_vec();
    let key = pem::parse(key_pem)?.contents().to_vec();
    let cas = pem::parse_many(ca_pem)?
        .into_iter()
        .map(|pem| pem.contents().to_vec())
        .collect::<Vec<_>>();
    let ca_refs = cas.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let archive = p12::PFX::new_with_cas(&certificate, &key, &ca_refs, password, name)
        .context("unable to create PKCS#12 archive")?;
    Ok(archive.to_der())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn keeps_acme_storage_roots_separate() {
        let root = std::env::temp_dir().join(format!("rust-acmesh-store-{}", uuid::Uuid::new_v4()));
        let store = Store::new(
            Some(root.join("home")),
            Some(root.join("config")),
            Some(root.join("certs")),
            Some(root.join("custom-account.conf")),
            Some(root.join("custom-domain.conf")),
        )
        .unwrap();
        assert_eq!(store.account_key(), root.join("home").join("account.key"));
        assert_eq!(store.account_conf(), root.join("custom-account.conf"));
        assert_eq!(
            store.domain_dir("example.com"),
            root.join("certs").join("example.com")
        );
        assert_eq!(
            store.domain_conf("example.com"),
            root.join("custom-domain.conf")
        );
    }

    #[cfg(feature = "pkcs12")]
    #[test]
    fn creates_readable_pkcs12() {
        let key = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec!["example.com".into()]).unwrap();
        let cert = params.self_signed(&key).unwrap();
        let bytes = pkcs12_bytes(
            cert.pem().as_bytes(),
            key.serialize_pem().as_bytes(),
            b"",
            "secret",
            "example.com",
        )
        .unwrap();
        let archive = p12::PFX::parse(&bytes).unwrap();
        assert_eq!(archive.cert_bags("secret").unwrap().len(), 1);
    }

    #[test]
    fn exports_domain_private_key_as_pkcs8() {
        let root = std::env::temp_dir().join(format!("rust-acmesh-pkcs8-{}", uuid::Uuid::new_v4()));
        let args = Args::try_parse_from([
            "rust-acmesh",
            "to-pkcs8",
            "-d",
            "example.com",
            "--home",
            root.to_str().unwrap(),
        ])
        .unwrap();
        let store = Store::new(args.home.clone(), None, None, None, None).unwrap();
        let input = store.domain_dir("example.com").join("key.pem");
        crate::crypto::create_domain_key(&input, true, Some("ec-384")).unwrap();
        to_pkcs8(&args, &store).unwrap();
        let output = store.domain_dir("example.com").join("domain.pkcs8");
        assert!(output.is_file());
        assert_eq!(
            crate::crypto::AccountKey::load(&output).unwrap().alg(),
            "ES384"
        );
    }
}
