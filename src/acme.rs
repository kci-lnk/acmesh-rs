use crate::{
    cli::{self, Args},
    crypto::{self, AccountKey},
    dns::Dns,
    storage::Store,
};
use anyhow::{Context, Result, bail};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use hmac::{Hmac, Mac};
use reqwest::{Client, Response};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::Sha256;
use std::{fs, path::Path, time::Duration};

const LE: &str = "https://acme-v02.api.letsencrypt.org/directory";
const LE_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";
const ZERO: &str = "https://acme.zerossl.com/v2/DV90";

#[derive(Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct Directory {
    new_nonce: String,
    new_account: String,
    new_order: String,
    revoke_cert: String,
}
struct Acme {
    client: Client,
    directory: Directory,
    key: AccountKey,
    account: String,
}

impl Acme {
    async fn new(args: &Args, store: &Store) -> Result<Self> {
        crypto::init_tls();
        let client = Client::builder()
            .danger_accept_invalid_certs(args.insecure)
            .build()?;
        let saved = crate::config::read_kv(&store.account_conf())
            .ok()
            .and_then(|conf| conf.get("CA_URL").cloned());
        let url = server_url(args.server.as_deref(), args.staging, saved.as_deref());
        let directory = acme_response(client.get(url).send().await?, "directory")
            .await?
            .json()
            .await?;
        let key = load_or_create_account(args, store)?;
        let account = account_url(store)?;
        Ok(Self {
            client,
            directory,
            key,
            account,
        })
    }
    async fn signed(&self, url: &str, payload: &Value) -> Result<Response> {
        let mut nonce = self
            .client
            .head(&self.directory.new_nonce)
            .send()
            .await?
            .headers()
            .get("Replay-Nonce")
            .context("ACME response has no Replay-Nonce")?
            .to_str()?
            .to_string();
        for attempt in 0..2 {
            let body = jws_with_kid(&self.key, &self.account, &nonce, url, payload)?;
            let response = self
                .client
                .post(url)
                .header("Content-Type", "application/jose+json")
                .json(&body)
                .send()
                .await?;
            if response.status().is_success() {
                return Ok(response);
            }
            let status = response.status();
            let fresh_nonce = response
                .headers()
                .get("Replay-Nonce")
                .and_then(|value| value.to_str().ok())
                .map(str::to_string);
            let detail = response.text().await.unwrap_or_default();
            let bad_nonce = serde_json::from_str::<Value>(&detail)
                .ok()
                .and_then(|value| value["type"].as_str().map(str::to_string))
                .is_some_and(|kind| kind.ends_with(":badNonce"));
            if attempt == 0
                && bad_nonce
                && let Some(fresh_nonce) = fresh_nonce
            {
                nonce = fresh_nonce;
                continue;
            }
            bail!("ACME signed request failed with HTTP {status}: {detail}");
        }
        unreachable!("ACME signed request retry loop always returns")
    }
}

async fn acme_response(response: Response, action: &str) -> Result<Response> {
    if response.status().is_success() {
        return Ok(response);
    }
    let status = response.status();
    let detail = response.text().await.unwrap_or_default();
    bail!("ACME {action} failed with HTTP {status}: {detail}")
}

fn jws_with_kid(
    key: &AccountKey,
    kid: &str,
    nonce: &str,
    url: &str,
    payload: &Value,
) -> Result<Value> {
    let protected = json!({ "alg": key.alg(), "kid": kid, "nonce": nonce, "url": url });
    let encoded = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&protected)?);
    let body = if payload.is_null() {
        String::new()
    } else {
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload)?)
    };
    let signature = URL_SAFE_NO_PAD.encode(key.sign(format!("{encoded}.{body}").as_bytes())?);
    Ok(json!({"protected":encoded,"payload":body,"signature":signature}))
}

pub async fn register_account(args: &Args, store: &Store) -> Result<()> {
    crypto::init_tls();
    let client = Client::builder()
        .danger_accept_invalid_certs(args.insecure)
        .build()?;
    let url = server_url(args.server.as_deref(), args.staging, None);
    let directory: Directory = acme_response(client.get(url.clone()).send().await?, "directory")
        .await?
        .json()
        .await?;
    let key = load_or_create_account(args, store)?;
    let nonce = client
        .head(&directory.new_nonce)
        .send()
        .await?
        .headers()
        .get("Replay-Nonce")
        .context("ACME response has no Replay-Nonce")?
        .to_str()?
        .to_string();
    let protected =
        json!({"alg":key.alg(),"jwk":key.jwk(),"nonce":nonce,"url":directory.new_account});
    let mut payload = json!({"termsOfServiceAgreed":true,"contact":args.email.as_ref().map(|e|vec![format!("mailto:{e}")]).unwrap_or_default()});
    let credentials = cli::credentials(args);
    if let (Some(kid), Some(hmac_key)) =
        (credentials.get("EAB_KID"), credentials.get("EAB_HMAC_KEY"))
    {
        payload["externalAccountBinding"] =
            eab_binding(&key, &directory.new_account, kid, hmac_key)?;
    } else if url.contains("zerossl.com") {
        bail!(
            "ZeroSSL requires EAB_KID and EAB_HMAC_KEY; pass them with --env or environment variables"
        );
    }
    let pe = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&protected)?);
    let pl = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload)?);
    let sig = URL_SAFE_NO_PAD.encode(key.sign(format!("{pe}.{pl}").as_bytes())?);
    let response = client
        .post(directory.new_account)
        .header("Content-Type", "application/jose+json")
        .json(&json!({"protected":pe,"payload":pl,"signature":sig}))
        .send()
        .await?;
    let response = acme_response(response, "account registration").await?;
    let location = response
        .headers()
        .get("Location")
        .context("ACME account response has no Location")?
        .to_str()?
        .to_string();
    let mut conf = crate::config::read_kv(&store.account_conf())?;
    conf.insert("ACCOUNT_URL".into(), location);
    conf.insert("CA_URL".into(), url);
    crate::config::write_kv(&store.account_conf(), &conf)?;
    println!("account registered");
    Ok(())
}

pub async fn issue(args: &Args, store: &Store) -> Result<()> {
    let domains = normalize_domains(&args.domains)?;
    let provider = args.dns.clone().context("--dns is required")?;
    if account_url(store).is_err() {
        register_account(args, store).await?;
    }
    let acme = Acme::new(args, store).await?;
    println!("[acme] creating order for {}", domains.join(", "));
    let order_response = acme.signed(&acme.directory.new_order, &json!({"identifiers":domains.iter().map(|d|json!({"type":"dns","value":d})).collect::<Vec<_>>()})).await?;
    let order_url = order_response
        .headers()
        .get("Location")
        .context("ACME order response has no Location")?
        .to_str()?
        .to_string();
    let mut order: Value = order_response.json().await?;
    order["url"] = json!(order_url);
    let mut credentials = crate::config::read_kv(&store.account_conf())?;
    credentials.extend(cli::credentials(args));
    let dns = Dns::new(&provider, credentials.clone(), args.insecure)?;
    if !args.no_save_credentials {
        let mut conf = crate::config::read_kv(&store.account_conf())?;
        let mut changed = false;
        for (key, value) in &credentials {
            if is_provider_secret(key) && conf.get(key) != Some(value) {
                conf.insert(key.clone(), value.clone());
                changed = true;
            }
        }
        if changed {
            crate::config::write_kv(&store.account_conf(), &conf)?;
        }
    }
    let thumb = crypto::thumbprint(&acme.key);
    let serial_challenges = serial_dns_challenges(&provider);
    let mut records = Vec::new();
    let issuance_result: Result<()> = async {
        for auth in order["authorizations"]
            .as_array()
            .context("ACME order has no authorizations")?
            .clone()
        {
            let auth_url = auth.as_str().context("invalid authorization URL")?;
            let av: Value = acme.signed(auth_url, &Value::Null).await?.json().await?;
            let challenge = av["challenges"]
                .as_array()
                .and_then(|x| x.iter().find(|x| x["type"] == "dns-01"))
                .context("CA did not provide DNS-01 challenge")?;
            let token = challenge["token"]
                .as_str()
                .context("challenge token missing")?;
            let challenge_url = challenge["url"]
                .as_str()
                .context("challenge URL missing")?
                .to_string();
            let domain = av["identifier"]["value"]
                .as_str()
                .context("authorization identifier missing")?;
            let name = format!("_acme-challenge.{domain}");
            let value = crypto::dns01_value(token, &thumb);
            println!("[dns] adding TXT {name}");
            dns.add_txt(&name, &value)
                .await
                .with_context(|| format!("add TXT {name}"))?;
            records.push((name.clone(), value.clone(), challenge_url.clone()));
            if serial_challenges {
                println!("[dns] waiting {} seconds for propagation", args.dnssleep);
                tokio::time::sleep(Duration::from_secs(args.dnssleep)).await;
                println!("[acme] triggering DNS-01 validation for {domain}");
                let _ = acme.signed(&challenge_url, &json!({})).await?;
                let mut authorization_valid = false;
                for _ in 0..40 {
                    tokio::time::sleep(Duration::from_secs(3)).await;
                    let authorization: Value =
                        acme.signed(auth_url, &Value::Null).await?.json().await?;
                    match authorization["status"].as_str() {
                        Some("valid") => {
                            authorization_valid = true;
                            break;
                        }
                        Some("invalid") => {
                            bail!("ACME authorization became invalid: {authorization}")
                        }
                        _ => {}
                    }
                }
                if !authorization_valid {
                    bail!("ACME authorization did not become valid for {domain}")
                }
                println!("[dns] removing TXT {name}");
                dns.remove_txt(&name, &value)
                    .await
                    .with_context(|| format!("remove TXT {name}"))?;
                records.pop();
            }
        }
        if !serial_challenges {
            println!("[dns] waiting {} seconds for propagation", args.dnssleep);
            tokio::time::sleep(Duration::from_secs(args.dnssleep)).await;
            println!("[acme] triggering DNS-01 validation");
            for (_, _, challenge_url) in &records {
                let _ = acme.signed(challenge_url, &json!({})).await?;
            }
        }
        for _ in 0..40 {
            tokio::time::sleep(Duration::from_secs(3)).await;
            order = acme.signed(&order_url, &Value::Null).await?.json().await?;
            order["url"] = json!(order_url);
            match order["status"].as_str() {
                Some("ready") | Some("valid") => break,
                Some("invalid") => bail!("ACME order became invalid: {order}"),
                _ => {}
            }
        }
        if order["status"] != "ready" && order["status"] != "valid" {
            bail!("ACME order did not become ready: {order}");
        }
        let domain = domains
            .iter()
            .find(|d| !d.starts_with("*."))
            .cloned()
            .unwrap_or_else(|| domains[0].clone());
        let dir = store.domain_dir(&domain);
        fs::create_dir_all(&dir)?;
        let key_path = dir.join("domain.key");
        if args.csr.is_none() && !key_path.exists() {
            crypto::create_domain_key(&key_path, args.ecc, args.keylength.as_deref())?;
        }
        if order["status"] == "ready" {
            println!("[acme] finalizing order");
            let csr = match &args.csr {
                Some(path) => csr_der(path)?,
                None => csr_for(&key_path, &domains)?,
            };
            order = acme
                .signed(
                    order["finalize"].as_str().context("finalize URL missing")?,
                    &json!({"csr":URL_SAFE_NO_PAD.encode(csr)}),
                )
                .await?
                .json()
                .await?;
        }
        for _ in 0..40 {
            if order["status"] == "valid" {
                break;
            }
            tokio::time::sleep(Duration::from_secs(3)).await;
            order = acme.signed(&order_url, &Value::Null).await?.json().await?;
        }
        let cert_url = order["certificate"]
            .as_str()
            .context("ACME certificate URL missing")?;
        println!("[acme] downloading certificate");
        let pem = acme.signed(cert_url, &Value::Null).await?.text().await?;
        let (leaf, issuer_chain) = split_pem_chain(&pem)?;
        fs::write(dir.join("cert.cer"), leaf)?;
        fs::write(dir.join("fullchain.cer"), &pem)?;
        fs::write(dir.join("ca.cer"), issuer_chain)?;
        if key_path.exists() {
            fs::copy(&key_path, dir.join("key.pem"))?;
        }
        let mut domain_conf = crate::config::read_kv(&store.domain_conf(&domain))?;
        domain_conf.insert("Le_Domain".into(), domain.clone());
        domain_conf.insert("Le_Alt".into(), domains.join(","));
        domain_conf.insert("Le_API".into(), provider);
        domain_conf.insert(
            "Le_CertPath".into(),
            dir.join("cert.cer").display().to_string(),
        );
        domain_conf.insert(
            "Le_KeyPath".into(),
            dir.join("key.pem").display().to_string(),
        );
        domain_conf.insert(
            "Le_FullChainPath".into(),
            dir.join("fullchain.cer").display().to_string(),
        );
        crate::config::write_kv(&store.domain_conf(&domain), &domain_conf)?;
        println!("certificate issued for {domain}");
        Ok(())
    }
    .await;
    let mut cleanup_errors = Vec::new();
    for (name, value, _) in records {
        println!("[dns] removing TXT {name}");
        if let Err(error) = dns.remove_txt(&name, &value).await {
            let message = format!("remove TXT {name}: {error:#}");
            eprintln!("[dns] cleanup failed: {message}");
            cleanup_errors.push(message);
        }
    }
    finish_issuance(issuance_result, cleanup_errors)
}

pub async fn renew(args: &Args, store: &Store) -> Result<()> {
    let mut renewal = args.clone();
    if renewal.domains.is_empty() {
        bail!("-d/--domain is required for manual --renew");
    }
    if renewal.dns.is_none() {
        let conf = crate::config::read_kv(&store.domain_conf(&renewal.domains[0]))?;
        renewal.dns = conf.get("Le_API").cloned();
    }
    issue(&renewal, store).await
}
pub async fn revoke(args: &Args, store: &Store) -> Result<()> {
    let domain = args.domains.first().context("-d/--domain is required")?;
    let pem = fs::read_to_string(store.domain_dir(domain).join("cert.cer"))
        .context("certificate is not available")?;
    let der = STANDARD.decode(
        pem.lines()
            .filter(|line| !line.starts_with("---"))
            .collect::<String>(),
    )?;
    let acme = Acme::new(args, store).await?;
    let response = acme
        .signed(
            &acme.directory.revoke_cert,
            &json!({"certificate":URL_SAFE_NO_PAD.encode(der),"reason":args.revoke_reason}),
        )
        .await?;
    if !response.status().is_success() {
        bail!(
            "certificate revocation failed: {}",
            response.text().await.unwrap_or_default()
        );
    }
    println!("certificate revoked for {domain}");
    Ok(())
}
fn normalize_domains(input: &[String]) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for raw in input {
        let d = raw.trim().trim_end_matches('.').to_ascii_lowercase();
        let h = d.strip_prefix("*.").unwrap_or(&d);
        if h.split('.').count() < 2
            || h.contains('*')
            || h.contains('/')
            || h.chars().any(char::is_whitespace)
        {
            bail!("invalid domain {d}");
        }
        if !out.contains(&d) {
            out.push(d);
        }
    }
    if out.is_empty() {
        bail!("-d/--domain is required")
    }
    Ok(out)
}
fn load_or_create_account(args: &Args, store: &Store) -> Result<AccountKey> {
    let p = args
        .accountkey
        .clone()
        .unwrap_or_else(|| store.account_key());
    if p.exists() {
        AccountKey::load(&p)
    } else {
        crypto::create_account_key(&p, args.ecc, args.accountkeylength.as_deref())?;
        AccountKey::load(&p)
    }
}
fn account_url(store: &Store) -> Result<String> {
    crate::config::read_kv(&store.account_conf())?
        .get("ACCOUNT_URL")
        .cloned()
        .context("ACME account is not registered; run --register-account")
}
fn server_url(requested: Option<&str>, staging: bool, saved: Option<&str>) -> String {
    if staging {
        return LE_STAGING.into();
    }
    match requested.or(saved) {
        Some("letsencrypt") | Some("letsencrypt.org") => LE.into(),
        Some("zerossl") | Some("zerossl.com") => ZERO.into(),
        Some(url) => url.to_string(),
        None => ZERO.into(),
    }
}
fn is_provider_secret(key: &str) -> bool {
    matches!(
        key,
        "CF_Token"
            | "CF_Zone_ID"
            | "CF_Account_ID"
            | "CF_Key"
            | "CF_Email"
            | "DP_Id"
            | "DP_Key"
            | "DP_Domain"
            | "Ali_Key"
            | "Ali_Secret"
            | "Ali_Domain"
            | "Tencent_SecretId"
            | "Tencent_SecretKey"
            | "GD_Key"
            | "GD_Secret"
            | "GD_Domain"
            | "HUAWEICLOUD_Username"
            | "HUAWEICLOUD_Password"
            | "HUAWEICLOUD_DomainName"
            | "HUAWEICLOUD_Region"
            | "HUAWEICLOUD_ProjectName"
            | "PORKBUN_API_KEY"
            | "PORKBUN_SECRET_API_KEY"
            | "PORKBUN_DOMAIN"
            | "BAIDU_ACCESS_KEY_ID"
            | "BAIDU_SECRET_ACCESS_KEY"
            | "BAIDU_DOMAIN"
            | "root_domain"
            | "Dynu_ClientId"
            | "Dynu_Secret"
            | "DYNV6_TOKEN"
            | "DuckDNS_Token"
    )
}

fn serial_dns_challenges(provider: &str) -> bool {
    provider.eq_ignore_ascii_case("dns_duckdns")
}

fn finish_issuance(issuance_result: Result<()>, cleanup_errors: Vec<String>) -> Result<()> {
    if cleanup_errors.is_empty() {
        return issuance_result;
    }
    let cleanup = cleanup_errors.join("; ");
    match issuance_result {
        Ok(()) => bail!("certificate issuance completed, but DNS cleanup failed: {cleanup}"),
        Err(error) => Err(error.context(format!("DNS cleanup also failed: {cleanup}"))),
    }
}
fn csr_for(path: &Path, domains: &[String]) -> Result<Vec<u8>> {
    let kp = rcgen::KeyPair::from_pem(&fs::read_to_string(path)?)?;
    let mut p = rcgen::CertificateParams::new(domains.to_vec())?;
    p.distinguished_name
        .push(rcgen::DnType::CommonName, domains[0].clone());
    Ok(p.serialize_request(&kp)?.der().to_vec())
}
fn csr_der(path: &Path) -> Result<Vec<u8>> {
    let text = fs::read_to_string(path)?;
    STANDARD
        .decode(
            text.lines()
                .filter(|line| !line.starts_with("---"))
                .collect::<String>(),
        )
        .context("invalid PEM CSR")
}
fn split_pem_chain(chain: &str) -> Result<(String, String)> {
    let marker = "-----END CERTIFICATE-----";
    let end = chain
        .find(marker)
        .context("ACME response does not contain a PEM certificate")?
        + marker.len();
    let leaf = format!("{}\n", chain[..end].trim());
    let issuer = format!("{}\n", chain[end..].trim());
    Ok((leaf, issuer))
}

fn eab_binding(key: &AccountKey, url: &str, kid: &str, encoded_key: &str) -> Result<Value> {
    type HmacSha256 = Hmac<Sha256>;
    let secret = URL_SAFE_NO_PAD
        .decode(encoded_key)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(encoded_key))?;
    let protected = URL_SAFE_NO_PAD.encode(serde_json::to_vec(
        &json!({"alg":"HS256","kid":kid,"url":url}),
    )?);
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&key.jwk())?);
    let mut mac = HmacSha256::new_from_slice(&secret)?;
    mac.update(format!("{protected}.{payload}").as_bytes());
    Ok(
        json!({"protected":protected,"payload":payload,"signature":URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persists_optional_dns_zone_configuration() {
        assert!(is_provider_secret("DP_Domain"));
        assert!(is_provider_secret("BAIDU_DOMAIN"));
        assert!(is_provider_secret("root_domain"));
    }

    #[test]
    fn duckdns_challenges_are_validated_serially() {
        assert!(serial_dns_challenges("dns_duckdns"));
        assert!(serial_dns_challenges("DNS_DUCKDNS"));
        assert!(!serial_dns_challenges("dns_cf"));
    }

    #[test]
    fn dns_cleanup_errors_are_returned_to_the_caller() {
        let error = finish_issuance(Ok(()), vec!["remove TXT failed".into()]).unwrap_err();
        assert!(error.to_string().contains("DNS cleanup failed"));

        let error = finish_issuance(
            Err(anyhow::anyhow!("issuance failed")),
            vec!["remove TXT failed".into()],
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("DNS cleanup also failed"));
        assert!(format!("{error:#}").contains("issuance failed"));
    }
    use axum::{
        Json, Router,
        body::Bytes,
        http::{HeaderName, HeaderValue, StatusCode},
        routing::{get, head, post},
    };
    use clap::Parser;
    use p256::ecdsa::{Signature, signature::Verifier};
    use p384::ecdsa::Signature as Signature384;
    use std::sync::{Arc, Mutex};
    use tokio::net::TcpListener;
    #[test]
    fn accepts_root_and_wildcard() {
        let d = normalize_domains(&["example.com".into(), "*.example.com".into()]).unwrap();
        assert_eq!(d.len(), 2);
    }
    #[test]
    fn rejects_nested_wildcard() {
        assert!(normalize_domains(&["foo.*.example.com".into()]).is_err());
    }
    #[test]
    fn splits_certificate_chain() {
        let (leaf, issuer) = split_pem_chain("-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nissuer\n-----END CERTIFICATE-----\n").unwrap();
        assert!(leaf.contains("leaf"));
        assert!(issuer.contains("issuer"));
    }

    #[test]
    fn jws_post_as_get_has_valid_es256_signature() {
        let key = AccountKey::generate_with_curve(true, 2048, false).unwrap();
        let jws = jws_with_kid(
            &key,
            "https://ca.test/account/1",
            "nonce-1",
            "https://ca.test/order/1",
            &Value::Null,
        )
        .unwrap();
        assert_eq!(jws["payload"], "");
        let protected = jws["protected"].as_str().unwrap();
        let decoded: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(protected).unwrap()).unwrap();
        assert_eq!(decoded["nonce"], "nonce-1");
        assert_eq!(decoded["url"], "https://ca.test/order/1");
        let signature = Signature::from_slice(
            &URL_SAFE_NO_PAD
                .decode(jws["signature"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
        match key {
            AccountKey::Ec(signing) => signing
                .verifying_key()
                .verify(format!("{protected}.").as_bytes(), &signature)
                .unwrap(),
            AccountKey::Ec384(_) | AccountKey::Rsa(_) => unreachable!(),
        }
    }

    #[test]
    fn jws_post_as_get_has_valid_es384_signature() {
        let key = AccountKey::generate_with_curve(true, 2048, true).unwrap();
        let jws = jws_with_kid(
            &key,
            "https://ca.test/account/1",
            "nonce-1",
            "https://ca.test/order/1",
            &Value::Null,
        )
        .unwrap();
        let protected = jws["protected"].as_str().unwrap();
        let signature = Signature384::from_slice(
            &URL_SAFE_NO_PAD
                .decode(jws["signature"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
        match key {
            AccountKey::Ec384(signing) => signing
                .verifying_key()
                .verify(format!("{protected}.").as_bytes(), &signature)
                .unwrap(),
            AccountKey::Ec(_) | AccountKey::Rsa(_) => unreachable!(),
        }
    }

    #[tokio::test]
    async fn registers_account_against_local_acme_directory() {
        let received = Arc::new(Mutex::new(None::<Value>));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let directory_origin = origin.clone();
        let account_origin = origin.clone();
        let capture = received.clone();
        let app = Router::new()
            .route("/directory", get(move || { let origin = directory_origin.clone(); async move { Json(json!({"newNonce":format!("{origin}/nonce"),"newAccount":format!("{origin}/account"),"newOrder":format!("{origin}/order"),"revokeCert":format!("{origin}/revoke")})) } }))
            .route("/nonce", head(|| async { [(HeaderName::from_static("replay-nonce"), HeaderValue::from_static("test-nonce"))] }))
            .route("/account", post(move |body: Bytes| { let capture = capture.clone(); let origin = account_origin.clone(); async move { *capture.lock().unwrap() = Some(serde_json::from_slice(&body).unwrap()); (StatusCode::CREATED, [(HeaderName::from_static("location"), HeaderValue::from_str(&format!("{origin}/account/1")).unwrap())], Json(json!({"status":"valid"}))) } }));
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let home =
            std::env::temp_dir().join(format!("rust-acmesh-acme-test-{}", uuid::Uuid::new_v4()));
        let args = Args::try_parse_from([
            "rust-acmesh",
            "register-account",
            "--server",
            &format!("{origin}/directory"),
            "--email",
            "test@example.com",
            "--home",
            home.to_str().unwrap(),
        ])
        .unwrap();
        let store = Store::new(args.home.clone(), None, None, None, None).unwrap();
        register_account(&args, &store).await.unwrap();
        assert_eq!(
            crate::config::read_kv(&store.account_conf()).unwrap()["ACCOUNT_URL"],
            format!("{origin}/account/1")
        );
        let request = received.lock().unwrap().clone().unwrap();
        let protected: Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(request["protected"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(protected["nonce"], "test-nonce");
        assert!(protected.get("jwk").is_some());
        server.abort();
    }

    #[tokio::test]
    async fn issues_certificate_through_local_acme_flow() {
        let key = rcgen::KeyPair::generate().unwrap();
        let certificate = rcgen::CertificateParams::new(vec!["example.com".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap()
            .pem();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let directory_origin = origin.clone();
        let account_origin = origin.clone();
        let order_origin = origin.clone();
        let order_poll_origin = origin.clone();
        let auth_origin = origin.clone();
        let wildcard_auth_origin = origin.clone();
        let finalize_origin = origin.clone();
        let certificate_body = certificate.clone();
        let app = Router::new()
            .route("/directory", get(move || { let origin=directory_origin.clone(); async move { Json(json!({"newNonce":format!("{origin}/nonce"),"newAccount":format!("{origin}/account"),"newOrder":format!("{origin}/order"),"revokeCert":format!("{origin}/revoke")})) } }))
            .route("/nonce", head(|| async { [(HeaderName::from_static("replay-nonce"), HeaderValue::from_static("test-nonce"))] }))
            .route("/account", post(move || { let origin=account_origin.clone(); async move { (StatusCode::CREATED, [(HeaderName::from_static("location"), HeaderValue::from_str(&format!("{origin}/account/1")).unwrap())], Json(json!({"status":"valid"}))) } }))
            .route("/order", post(move || { let origin=order_origin.clone(); async move { (StatusCode::CREATED, [(HeaderName::from_static("location"), HeaderValue::from_str(&format!("{origin}/order/1")).unwrap())], Json(json!({"status":"pending","authorizations":[format!("{origin}/auth/1"),format!("{origin}/auth/2")],"finalize":format!("{origin}/finalize/1")}))) } }))
            .route("/order/1", post(move || { let origin=order_poll_origin.clone(); async move { Json(json!({"status":"ready","finalize":format!("{origin}/finalize/1")})) } }))
            .route("/auth/1", post(move || { let origin=auth_origin.clone(); async move { Json(json!({"identifier":{"type":"dns","value":"example.com"},"challenges":[{"type":"dns-01","token":"challenge-token","url":format!("{origin}/challenge/1")}]})) } }))
            .route("/auth/2", post(move || { let origin=wildcard_auth_origin.clone(); async move { Json(json!({"identifier":{"type":"dns","value":"example.com"},"wildcard":true,"challenges":[{"type":"dns-01","token":"wildcard-challenge-token","url":format!("{origin}/challenge/2")}]})) } }))
            .route("/challenge/1", post(|| async { Json(json!({"status":"pending"})) }))
            .route("/challenge/2", post(|| async { Json(json!({"status":"pending"})) }))
            .route("/finalize/1", post(move || { let origin=finalize_origin.clone(); async move { Json(json!({"status":"valid","certificate":format!("{origin}/cert/1")})) } }))
            .route("/cert/1", post(move || { let certificate=certificate_body.clone(); async move { certificate } }));
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let home =
            std::env::temp_dir().join(format!("rust-acmesh-issue-test-{}", uuid::Uuid::new_v4()));
        let args = Args::try_parse_from([
            "rust-acmesh",
            "issue",
            "--server",
            &format!("{origin}/directory"),
            "--dns",
            "dns_test",
            "--dnssleep",
            "0",
            "--ecc",
            "-d",
            "example.com",
            "-d",
            "*.example.com",
            "--home",
            home.to_str().unwrap(),
        ])
        .unwrap();
        let store = Store::new(args.home.clone(), None, None, None, None).unwrap();
        issue(&args, &store).await.unwrap();
        assert!(store.domain_dir("example.com").join("cert.cer").is_file());
        assert!(store.domain_dir("example.com").join("key.pem").is_file());
        assert_eq!(
            crate::config::read_kv(&store.domain_conf("example.com")).unwrap()["Le_API"],
            "dns_test"
        );
        assert_eq!(
            crate::config::read_kv(&store.domain_conf("example.com")).unwrap()["Le_Alt"],
            "example.com,*.example.com"
        );
        server.abort();
    }
}
