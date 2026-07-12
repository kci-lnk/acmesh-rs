use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use hmac::{Hmac, Mac};
use reqwest::Client;
use serde_json::{Value, json};
use sha1::Sha1;
use sha2::Sha256 as Sha2;
use std::{collections::HashMap, time::Duration};

#[derive(Clone)]
pub struct Dns {
    client: Client,
    provider: String,
    vars: HashMap<String, String>,
}
impl Dns {
    pub fn new(provider: &str, vars: HashMap<String, String>, insecure: bool) -> Result<Self> {
        crate::crypto::init_tls();
        let client = Client::builder()
            .danger_accept_invalid_certs(insecure)
            .timeout(Duration::from_secs(30))
            .build()?;
        Ok(Self {
            client,
            provider: provider.to_ascii_lowercase(),
            vars,
        })
    }
    pub async fn add_txt(&self, name: &str, value: &str) -> Result<()> {
        self.mutate(true, name, value).await
    }
    pub async fn remove_txt(&self, name: &str, value: &str) -> Result<()> {
        self.mutate(false, name, value).await
    }
    async fn mutate(&self, add: bool, name: &str, value: &str) -> Result<()> {
        match self.provider.as_str() {
            #[cfg(test)]
            "dns_test" => Ok(()),
            "dns_cf" | "cloudflare" => self.cloudflare(add, name, value).await,
            "dns_dp" | "dnspod" => self.dnspod(add, name, value).await,
            "dns_duckdns" => self.duckdns(add, name, value).await,
            "dns_gd" => self.godaddy(add, name, value).await,
            "dns_porkbun" => self.porkbun(add, name, value).await,
            "dns_dynv6" => self.dynv6(add, name, value).await,
            "dns_ali" | "alidns" => self.alidns(add, name, value).await,
            "dns_dynu" => self.dynu(add, name, value).await,
            "dns_tencent" => self.tencent(add, name, value).await,
            "dns_baiducloud" => self.baiducloud(add, name, value).await,
            "dns_noip" => bail!(
                "dns_noip is a dynamic-IP service and does not expose DNS-01 TXT record management"
            ),
            "dns_huaweicloud" => self.huaweicloud(add, name, value).await,
            _ => bail!(
                "unsupported DNS provider {}; supported: dns_ali,dns_baiducloud,dns_cf,dns_dp,dns_duckdns,dns_dynu,dns_dynv6,dns_gd,dns_huaweicloud,dns_noip,dns_porkbun,dns_tencent",
                self.provider
            ),
        }
    }
    async fn cloudflare(&self, add: bool, name: &str, value: &str) -> Result<()> {
        let token = self
            .vars
            .get("CF_Token")
            .or_else(|| self.vars.get("api_token"));
        let global_key = self.vars.get("CF_Key");
        let email = self.vars.get("CF_Email");
        if token.is_none() && (global_key.is_none() || email.is_none()) {
            bail!("Cloudflare requires CF_Token or both CF_Key and CF_Email");
        }
        let zone = match self
            .vars
            .get("CF_Zone_ID")
            .or_else(|| self.vars.get("zone_id"))
        {
            Some(zone) => zone.clone(),
            None => {
                self.cloudflare_zone_id(name, token, global_key, email)
                    .await?
            }
        };
        let base = format!("https://api.cloudflare.com/client/v4/zones/{zone}/dns_records");
        if add {
            let r = cloudflare_auth(self.client.post(&base), token, global_key, email)
                .json(&json!({"type":"TXT","name":name,"content":value,"ttl":120}))
                .send()
                .await?;
            let response: Value = r.error_for_status()?.json().await?;
            if response["success"] == true || cloudflare_duplicate(&response) {
                Ok(())
            } else {
                bail!("Cloudflare create TXT record failed: {response}")
            }
        } else {
            let r = cloudflare_auth(self.client.get(&base), token, global_key, email)
                .query(&[("type", "TXT"), ("name", name)])
                .send()
                .await?;
            let v: Value = r.error_for_status()?.json().await?;
            if let Some(id) = v["result"]
                .as_array()
                .and_then(|a| a.iter().find(|x| x["content"] == value))
                .and_then(|x| x["id"].as_str())
            {
                ensure_api(
                    cloudflare_auth(
                        self.client.delete(format!("{base}/{id}")),
                        token,
                        global_key,
                        email,
                    )
                    .send()
                    .await?,
                )
                .await?;
            }
            Ok(())
        }
    }
    async fn cloudflare_zone_id(
        &self,
        name: &str,
        token: Option<&String>,
        global_key: Option<&String>,
        email: Option<&String>,
    ) -> Result<String> {
        for candidate in zone_candidates(name) {
            let response: Value = cloudflare_auth(
                self.client
                    .get("https://api.cloudflare.com/client/v4/zones"),
                token,
                global_key,
                email,
            )
            .query(&[("name", candidate.as_str()), ("status", "active")])
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
            if let Some(id) = response["result"]
                .as_array()
                .and_then(|zones| zones.iter().find(|zone| zone["name"] == candidate))
                .and_then(|zone| zone["id"].as_str())
            {
                return Ok(id.to_string());
            }
        }
        bail!("Cloudflare zone was not found; grant Zone Read or pass CF_Zone_ID")
    }
    async fn dnspod(&self, add: bool, name: &str, value: &str) -> Result<()> {
        let id = self
            .vars
            .get("DP_Id")
            .or_else(|| self.vars.get("id"))
            .context("DP_Id is required")?;
        let key = self
            .vars
            .get("DP_Key")
            .or_else(|| self.vars.get("key"))
            .context("DP_Key is required")?;
        let root = match self
            .vars
            .get("DP_Domain")
            .or_else(|| self.vars.get("domain"))
        {
            Some(root) => root.clone(),
            None => self.dnspod_zone(name, id, key).await?,
        };
        let sub = name.strip_suffix(&format!(".{root}")).unwrap_or("@");
        let list = self
            .client
            .post("https://dnsapi.cn/Record.List")
            .form(&[
                ("login_token", format!("{id},{key}")),
                ("format", "json".into()),
                ("domain", root.clone()),
                ("sub_domain", sub.to_string()),
                ("record_type", "TXT".into()),
            ])
            .send()
            .await?
            .error_for_status()?
            .json::<Value>()
            .await?;
        if add {
            let r = self
                .client
                .post("https://dnsapi.cn/Record.Create")
                .form(&[
                    ("login_token", format!("{id},{key}")),
                    ("format", "json".into()),
                    ("domain", root.clone()),
                    ("sub_domain", sub.to_string()),
                    ("record_type", "TXT".into()),
                    ("record_line", "默认".into()),
                    ("value", value.to_string()),
                ])
                .send()
                .await?;
            let v: Value = r.error_for_status()?.json().await?;
            if v["status"]["code"] != "1" {
                bail!("DNSPod add failed: {}", v);
            }
        } else if let Some(record_id) = list["records"]
            .as_array()
            .and_then(|a| a.iter().find(|x| x["value"] == value))
            .and_then(|x| x["id"].as_str())
        {
            let r = self
                .client
                .post("https://dnsapi.cn/Record.Remove")
                .form(&[
                    ("login_token", format!("{id},{key}")),
                    ("format", "json".into()),
                    ("domain", root.clone()),
                    ("record_id", record_id.to_string()),
                ])
                .send()
                .await?;
            let v: Value = r.error_for_status()?.json().await?;
            if v["status"]["code"] != "1" {
                bail!("DNSPod remove failed: {}", v);
            }
        }
        Ok(())
    }
    async fn dnspod_zone(&self, name: &str, id: &str, key: &str) -> Result<String> {
        for candidate in zone_candidates(name) {
            let response: Value = self
                .client
                .post("https://dnsapi.cn/Domain.Info")
                .form(&[
                    ("login_token", format!("{id},{key}")),
                    ("format", "json".into()),
                    ("domain", candidate.clone()),
                ])
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            if response["status"]["code"] == "1" {
                return Ok(candidate);
            }
        }
        bail!("DNSPod zone was not found; pass DP_Domain for a delegated zone")
    }
    async fn duckdns(&self, add: bool, name: &str, value: &str) -> Result<()> {
        let token = self
            .vars
            .get("DuckDNS_Token")
            .or_else(|| self.vars.get("token"))
            .context("DuckDNS_Token is required")?;
        let host = name
            .strip_prefix("_acme-challenge.")
            .unwrap_or(name)
            .split('.')
            .next()
            .unwrap_or(name);
        let txt = if add { value } else { "" };
        let v: Value = self
            .client
            .get("https://www.duckdns.org/update")
            .query(&[("domains", host), ("token", token), ("txt", txt)])
            .send()
            .await?
            .error_for_status()?
            .json()
            .await
            .unwrap_or_else(|_| json!("OK"));
        if v.as_str() != Some("OK") && v != json!("OK") {
            bail!("DuckDNS update failed: {v}");
        }
        Ok(())
    }
    async fn godaddy(&self, add: bool, name: &str, value: &str) -> Result<()> {
        let key = self
            .vars
            .get("GD_Key")
            .or_else(|| self.vars.get("api_key"))
            .context("GD_Key is required")?;
        let secret = self
            .vars
            .get("GD_Secret")
            .or_else(|| self.vars.get("api_secret"))
            .context("GD_Secret is required")?;
        let (root, sub) = root_sub(name, self.vars.get("GD_Domain").map(String::as_str));
        let url = format!("https://api.godaddy.com/v1/domains/{root}/records/TXT/{sub}");
        let auth = format!("sso-key {key}:{secret}");
        let existing: Value = self
            .client
            .get(&url)
            .header("Authorization", &auth)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let mut records = existing.as_array().map(|items|items.iter().filter_map(|record|record.get("data").and_then(Value::as_str).map(|data|json!({"data":data,"ttl":record.get("ttl").and_then(Value::as_u64).unwrap_or(600)}))).collect::<Vec<_>>()).unwrap_or_default();
        if add {
            if records.iter().any(|record| record["data"] == value) {
                return Ok(());
            }
            records.push(json!({"data":value,"ttl":600}));
            self.client
                .put(&url)
                .header("Authorization", auth)
                .json(&records)
                .send()
                .await?
                .error_for_status()?;
        } else {
            records.retain(|record| record["data"] != value);
            if records.is_empty() {
                self.client
                    .delete(&url)
                    .header("Authorization", auth)
                    .send()
                    .await?
                    .error_for_status()?;
            } else {
                self.client
                    .put(&url)
                    .header("Authorization", auth)
                    .json(&records)
                    .send()
                    .await?
                    .error_for_status()?;
            }
        }
        Ok(())
    }
    async fn porkbun(&self, add: bool, name: &str, value: &str) -> Result<()> {
        let api = self
            .vars
            .get("PORKBUN_API_KEY")
            .context("PORKBUN_API_KEY is required")?;
        let secret = self
            .vars
            .get("PORKBUN_SECRET_API_KEY")
            .context("PORKBUN_SECRET_API_KEY is required")?;
        let (root, sub) = root_sub(name, self.vars.get("PORKBUN_DOMAIN").map(String::as_str));
        if add {
            let v:Value=self.client.post(format!("https://porkbun.com/api/json/v3/dns/create/{root}")).json(&json!({"apikey":api,"secretapikey":secret,"name":sub,"type":"TXT","content":value,"ttl":300})).send().await?.error_for_status()?.json().await?;
            if v["status"] != "SUCCESS" {
                bail!("Porkbun add failed: {v}");
            }
        } else {
            let records: Value = self
                .client
                .post(format!(
                    "https://porkbun.com/api/json/v3/dns/retrieve/{root}"
                ))
                .json(&json!({"apikey":api,"secretapikey":secret}))
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            if let Some(id) = records["records"]
                .as_array()
                .and_then(|rs| {
                    rs.iter()
                        .find(|r| r["type"] == "TXT" && r["name"] == sub && r["content"] == value)
                })
                .and_then(|r| r["id"].as_str())
            {
                let result: Value = self
                    .client
                    .post(format!(
                        "https://porkbun.com/api/json/v3/dns/delete/{root}/{id}"
                    ))
                    .json(&json!({"apikey":api,"secretapikey":secret}))
                    .send()
                    .await?
                    .error_for_status()?
                    .json()
                    .await?;
                if result["status"] != "SUCCESS" {
                    bail!("Porkbun delete failed: {result}");
                }
            }
        }
        Ok(())
    }
    async fn dynv6(&self, add: bool, name: &str, value: &str) -> Result<()> {
        let token = self
            .vars
            .get("DYNV6_TOKEN")
            .or_else(|| self.vars.get("token"))
            .context("DYNV6_TOKEN is required")?;
        let host = name.strip_prefix("_acme-challenge.").unwrap_or(name);
        let r = self
            .client
            .get("https://dynv6.com/api/update")
            .query(&[
                ("hostname", host),
                ("token", token),
                ("txt", if add { value } else { "" }),
            ])
            .send()
            .await?
            .error_for_status()?;
        let text = r.text().await?;
        if !text.contains("good") && !text.contains("nochg") {
            bail!("dynv6 update failed: {text}");
        }
        Ok(())
    }
    async fn alidns(&self, add: bool, name: &str, value: &str) -> Result<()> {
        let id = self
            .vars
            .get("Ali_Key")
            .or_else(|| self.vars.get("access_key_id"))
            .context("Ali_Key is required")?;
        let secret = self
            .vars
            .get("Ali_Secret")
            .or_else(|| self.vars.get("access_key_secret"))
            .context("Ali_Secret is required")?;
        let (root, rr) = root_sub(name, self.vars.get("Ali_Domain").map(String::as_str));
        let mut common = vec![
            ("AccessKeyId", id.clone()),
            (
                "Action",
                if add {
                    "AddDomainRecord".into()
                } else {
                    "DescribeDomainRecords".into()
                },
            ),
            ("Format", "JSON".into()),
            ("SignatureMethod", "HMAC-SHA1".into()),
            ("SignatureNonce", uuid_nonce()),
            ("SignatureVersion", "1.0".into()),
            ("Timestamp", time_stamp()),
            ("Version", "2015-01-09".into()),
            ("DomainName", root.clone()),
        ];
        if add {
            common.push(("RR", rr));
            common.push(("RRType", "TXT".into()));
            common.push(("Value", value.into()));
        } else {
            common.push(("RRKeyWord", rr));
            common.push(("Type", "TXT".into()));
        }
        let v = self.ali_request(common, secret).await?;
        if add {
            if v["RecordId"].as_str().is_none() {
                bail!("AliDNS add failed: {v}");
            }
        } else if let Some(record) = v["DomainRecords"]["Record"]
            .as_array()
            .and_then(|x| x.iter().find(|r| r["Value"] == value))
            .and_then(|r| r["RecordId"].as_str())
        {
            let params = vec![
                ("AccessKeyId", id.clone()),
                ("Action", "DeleteDomainRecord".into()),
                ("Format", "JSON".into()),
                ("RecordId", record.into()),
                ("SignatureMethod", "HMAC-SHA1".into()),
                ("SignatureNonce", uuid_nonce()),
                ("SignatureVersion", "1.0".into()),
                ("Timestamp", time_stamp()),
                ("Version", "2015-01-09".into()),
            ];
            let _ = self.ali_request(params, secret).await?;
        }
        Ok(())
    }
    async fn dynu(&self, add: bool, name: &str, value: &str) -> Result<()> {
        let id = self
            .vars
            .get("Dynu_ClientId")
            .context("Dynu_ClientId is required")?;
        let secret = self
            .vars
            .get("Dynu_Secret")
            .context("Dynu_Secret is required")?;
        let auth = STANDARD.encode(format!("{id}:{secret}"));
        let token: Value = self
            .client
            .get("https://api.dynu.com/v2/oauth2/token")
            .header("Authorization", format!("Basic {auth}"))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let token = token["access_token"]
            .as_str()
            .context("Dynu did not return access_token")?;
        let parts: Vec<_> = name.split('.').collect();
        let mut found = None;
        for i in 1..parts.len() {
            let root = parts[i..].join(".");
            let v: Value = self
                .client
                .get(format!("https://api.dynu.com/v2/dns/getroot/{root}"))
                .bearer_auth(token)
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            if v["domainName"].as_str() == Some(root.as_str()) {
                found = Some((
                    root,
                    parts[..i].join("."),
                    v["id"]
                        .as_i64()
                        .or_else(|| v["domainId"].as_i64())
                        .context("Dynu root response has no id")?,
                ));
                break;
            }
        }
        let (_, node, domain_id) = found.context("Dynu zone not found")?;
        let base = format!("https://api.dynu.com/v2/dns/{domain_id}/record");
        if add {
            self.client.post(&base).bearer_auth(token).json(&json!({"domainId":domain_id,"nodeName":node,"recordType":"TXT","textData":value,"state":true,"ttl":90})).send().await?.error_for_status()?;
        } else {
            let list: Value = self
                .client
                .get(&base)
                .bearer_auth(token)
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            if let Some(record) = list
                .as_array()
                .and_then(|a| a.iter().find(|x| x["textData"] == value))
                .and_then(|x| x["id"].as_i64())
            {
                self.client
                    .delete(format!("{base}/{record}"))
                    .bearer_auth(token)
                    .send()
                    .await?
                    .error_for_status()?;
            }
        }
        Ok(())
    }
    async fn tencent(&self, add: bool, name: &str, value: &str) -> Result<()> {
        let id = self
            .vars
            .get("Tencent_SecretId")
            .context("Tencent_SecretId is required")?;
        let secret = self
            .vars
            .get("Tencent_SecretKey")
            .context("Tencent_SecretKey is required")?;
        let parts: Vec<_> = name.split('.').collect();
        let mut found = None;
        for i in 1..parts.len() {
            let root = parts[i..].join(".");
            if self
                .tencent_call(
                    id,
                    secret,
                    "DescribeRecordList",
                    json!({"Domain":root,"Limit":1}),
                )
                .await
                .is_ok()
            {
                found = Some((root, parts[..i].join(".")));
                break;
            }
        }
        let (domain, sub) = found.context("Tencent Cloud DNS zone not found")?;
        if add {
            self.tencent_call(id,secret,"CreateRecord",json!({"Domain":domain,"SubDomain":sub,"RecordType":"TXT","RecordLine":"默认","Value":value,"TTL":600})).await?;
        } else {
            let records = self
                .tencent_call(
                    id,
                    secret,
                    "DescribeRecordFilterList",
                    json!({"Domain":domain,"SubDomain":sub,"RecordValue":value}),
                )
                .await?;
            if let Some(record_id) = records["Response"]["RecordList"]
                .as_array()
                .and_then(|a| a.first())
                .and_then(|v| v["RecordId"].as_i64())
            {
                self.tencent_call(
                    id,
                    secret,
                    "DeleteRecord",
                    json!({"Domain":domain,"RecordId":record_id}),
                )
                .await?;
            }
        }
        Ok(())
    }
    async fn tencent_call(
        &self,
        id: &str,
        secret: &str,
        action: &str,
        payload: Value,
    ) -> Result<Value> {
        let host = "dnspod.tencentcloudapi.com";
        let service = "dnspod";
        let version = "2021-03-23";
        let timestamp = time::OffsetDateTime::now_utc().unix_timestamp();
        let date = time::OffsetDateTime::from_unix_timestamp(timestamp)?
            .date()
            .to_string();
        let action_lower = action.to_ascii_lowercase();
        let body = serde_json::to_string(&payload)?;
        let canonical_headers =
            format!("content-type:application/json\nhost:{host}\nx-tc-action:{action_lower}\n");
        let signed = "content-type;host;x-tc-action";
        let canonical = format!(
            "POST\n/\n\n{canonical_headers}\n{signed}\n{}",
            sha256_hex(body.as_bytes())
        );
        let scope = format!("{date}/{service}/tc3_request");
        let text = format!(
            "TC3-HMAC-SHA256\n{timestamp}\n{scope}\n{}",
            sha256_hex(canonical.as_bytes())
        );
        let k_date = hmac256(format!("TC3{secret}").as_bytes(), date.as_bytes())?;
        let k_service = hmac256(&k_date, service.as_bytes())?;
        let k_signing = hmac256(&hmac256(&k_service, b"tc3_request")?, text.as_bytes())?;
        let authorization = format!(
            "TC3-HMAC-SHA256 Credential={id}/{scope}, SignedHeaders={signed}, Signature={}",
            hex(&k_signing)
        );
        let response = self
            .client
            .post(format!("https://{host}/"))
            .header("Content-Type", "application/json")
            .header("Authorization", authorization)
            .header("X-TC-Version", version)
            .header("X-TC-Timestamp", timestamp)
            .header("X-TC-Action", action)
            .body(body)
            .send()
            .await?
            .error_for_status()?;
        let v: Value = response.json().await?;
        if v["Response"]["Error"].is_object() {
            bail!("Tencent API error: {}", v["Response"]["Error"])
        }
        Ok(v)
    }
    async fn huaweicloud(&self, add: bool, name: &str, value: &str) -> Result<()> {
        let username = self
            .vars
            .get("HUAWEICLOUD_Username")
            .context("HUAWEICLOUD_Username is required")?;
        let password = self
            .vars
            .get("HUAWEICLOUD_Password")
            .context("HUAWEICLOUD_Password is required")?;
        let domain = self
            .vars
            .get("HUAWEICLOUD_DomainName")
            .context("HUAWEICLOUD_DomainName is required")?;
        let region = self
            .vars
            .get("HUAWEICLOUD_Region")
            .map(String::as_str)
            .unwrap_or("ap-southeast-1");
        let project = self
            .vars
            .get("HUAWEICLOUD_ProjectName")
            .map(String::as_str)
            .unwrap_or(region);
        let endpoint = format!("https://dns.{region}.myhuaweicloud.com");
        let token_response=self.client.post("https://iam.myhuaweicloud.com/v3/auth/tokens").json(&json!({"auth":{"identity":{"methods":["password"],"password":{"user":{"name":username,"password":password,"domain":{"name":domain}}}},"scope":{"project":{"name":project}}}})).send().await?.error_for_status()?;
        let token = token_response
            .headers()
            .get("X-Subject-Token")
            .context("HuaweiCloud did not return X-Subject-Token")?
            .to_str()?
            .to_string();
        let parts: Vec<_> = name.split('.').collect();
        let mut zone = None;
        for i in 1..parts.len() {
            let root = parts[i..].join(".");
            let result: Value = self
                .client
                .get(format!("{endpoint}/v2/zones"))
                .header("X-Auth-Token", &token)
                .query(&[("name", root.as_str())])
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            if let Some(z) = result["zones"].as_array().and_then(|z| {
                z.iter()
                    .find(|z| z["name"].as_str() == Some(format!("{root}.").as_str()))
            }) {
                zone = Some((
                    z["id"]
                        .as_str()
                        .context("HuaweiCloud zone id missing")?
                        .to_string(),
                    root,
                ));
                break;
            }
        }
        let (zone_id, _root) = zone.context("HuaweiCloud zone not found")?;
        let endpoint = format!("{endpoint}/v2/zones/{zone_id}/recordsets");
        let existing: Value = self
            .client
            .get(&endpoint)
            .header("X-Auth-Token", &token)
            .query(&[("name", name), ("status", "ACTIVE")])
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let recordset = existing["recordsets"].as_array().and_then(|x| x.first());
        let quoted = format!("\"{value}\"");
        if add {
            let mut records = recordset
                .and_then(|r| r["records"].as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str())
                        .map(String::from)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            if !records.contains(&quoted) {
                records.push(quoted);
            }
            let body = json!({"name":format!("{name}."),"description":"ACME Challenge","type":"TXT","ttl":1,"records":records});
            if let Some(id) = recordset.and_then(|r| r["id"].as_str()) {
                self.client
                    .put(format!("{endpoint}/{id}"))
                    .header("X-Auth-Token", &token)
                    .json(&body)
                    .send()
                    .await?
                    .error_for_status()?;
            } else {
                self.client
                    .post(&endpoint)
                    .header("X-Auth-Token", &token)
                    .json(&body)
                    .send()
                    .await?
                    .error_for_status()?;
            }
        } else if let Some(record) = recordset {
            let id = record["id"]
                .as_str()
                .context("HuaweiCloud recordset id missing")?;
            let mut records = record["records"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str())
                        .map(String::from)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            records.retain(|v| v != &quoted);
            if records.is_empty() {
                self.client
                    .delete(format!("{endpoint}/{id}"))
                    .header("X-Auth-Token", &token)
                    .send()
                    .await?
                    .error_for_status()?;
            } else {
                self.client.put(format!("{endpoint}/{id}")).header("X-Auth-Token",&token).json(&json!({"name":format!("{name}."),"description":"ACME Challenge","type":"TXT","ttl":1,"records":records})).send().await?.error_for_status()?;
            }
        }
        Ok(())
    }
    async fn baiducloud(&self, add: bool, name: &str, value: &str) -> Result<()> {
        let access = self
            .vars
            .get("BAIDU_ACCESS_KEY_ID")
            .or_else(|| self.vars.get("access_key_id"))
            .context("BAIDU_ACCESS_KEY_ID is required")?;
        let secret = self
            .vars
            .get("BAIDU_SECRET_ACCESS_KEY")
            .or_else(|| self.vars.get("secret_access_key"))
            .context("BAIDU_SECRET_ACCESS_KEY is required")?;
        let (root, record) = root_sub(name, self.vars.get("root_domain").map(String::as_str));
        let list = self
            .baidu_call(
                access,
                secret,
                "/v1/domain/resolve/list",
                json!({"domain":root,"pageNum":1,"pageSize":1000}),
            )
            .await?;
        let existing = list["result"].as_array().and_then(|rs| {
            rs.iter()
                .find(|r| r["domain"] == record && r["rdType"] == "TXT" && r["rdata"] == value)
        });
        if add {
            if existing.is_none() {
                let response = self.baidu_call(access,secret,"/v1/domain/resolve/add",json!({"domain":record,"rdType":"TXT","ttl":300,"rdata":value,"zoneName":root})).await?;
                baidu_ok(&response)?;
            }
        } else if let Some(id) = existing.and_then(|r| r["recordId"].as_i64()) {
            let response = self
                .baidu_call(
                    access,
                    secret,
                    "/v1/domain/resolve/delete",
                    json!({"recordId":id}),
                )
                .await?;
            baidu_ok(&response)?;
        }
        Ok(())
    }
    async fn baidu_call(
        &self,
        access: &str,
        secret: &str,
        path: &str,
        body: Value,
    ) -> Result<Value> {
        let url = format!("https://bcd.baidubce.com{path}");
        let timestamp = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)?;
        let timestamp = timestamp.trim_end_matches('Z').replace("+00:00", "") + "Z";
        let prefix = format!("bce-auth-v1/{access}/{timestamp}/1800");
        let headers = "content-type:application%2Fjson\nhost:bcd.baidubce.com\nx-bce-date:"
            .to_string()
            + &enc(&timestamp);
        let signing_key = hex(&hmac256(secret.as_bytes(), prefix.as_bytes())?);
        let canonical = format!("POST\n{path}\n\n{headers}");
        let signature = hex(&hmac256(signing_key.as_bytes(), canonical.as_bytes())?);
        let authorization = format!("{prefix}/content-type;host;x-bce-date/{signature}");
        let response = self
            .client
            .post(url)
            .header("Content-Type", "application/json")
            .header("Host", "bcd.baidubce.com")
            .header("x-bce-date", timestamp)
            .header("Authorization", authorization)
            .json(&body)
            .send()
            .await?
            .error_for_status()?;
        Ok(response.json().await?)
    }
    async fn ali_request(&self, mut params: Vec<(&str, String)>, secret: &str) -> Result<Value> {
        params.sort_by(|a, b| a.0.cmp(b.0));
        let canonical = params
            .iter()
            .map(|(k, v)| format!("{}={}", enc(k), enc(v)))
            .collect::<Vec<_>>()
            .join("&");
        let sign_src = format!("GET&%2F&{}", enc(&canonical));
        let mut mac = Hmac::<Sha1>::new_from_slice(format!("{secret}&").as_bytes())?;
        mac.update(sign_src.as_bytes());
        let sig = STANDARD.encode(mac.finalize().into_bytes());
        let mut q = canonical;
        q.push_str("&Signature=");
        q.push_str(&enc(&sig));
        Ok(self
            .client
            .get("https://alidns.aliyuncs.com/")
            .query(
                &q.split('&')
                    .filter_map(|p| p.split_once('='))
                    .collect::<Vec<_>>(),
            )
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }
}
fn root_sub(name: &str, configured: Option<&str>) -> (String, String) {
    let clean = name.strip_prefix("_acme-challenge.").unwrap_or(name);
    let root = configured.map(str::to_string).unwrap_or_else(|| {
        let p: Vec<_> = clean.split('.').collect();
        if p.len() >= 2 {
            p[p.len() - 2..].join(".")
        } else {
            clean.to_string()
        }
    });
    let sub = clean
        .strip_suffix(&format!(".{root}"))
        .unwrap_or("")
        .to_string();
    (root, if sub.is_empty() { "@".into() } else { sub })
}
fn zone_candidates(name: &str) -> Vec<String> {
    let clean = name
        .trim_end_matches('.')
        .strip_prefix("_acme-challenge.")
        .unwrap_or(name);
    let labels = clean.split('.').collect::<Vec<_>>();
    (0..labels.len().saturating_sub(1))
        .map(|index| labels[index..].join("."))
        .collect()
}
fn enc(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}
fn uuid_nonce() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex(&bytes)
}
fn time_stamp() -> String {
    format!(
        "{}Z",
        time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap()
            .trim_end_matches('Z')
    )
}
fn hmac256(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let mut mac = Hmac::<Sha2>::new_from_slice(key)?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}
fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    hex(&Sha2::digest(data))
}
fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}
fn baidu_ok(value: &Value) -> Result<()> {
    if let Some(code) = value["code"].as_str() {
        bail!(
            "Baidu Cloud DNS API error {code}: {}",
            value["message"].as_str().unwrap_or("unknown error")
        );
    }
    Ok(())
}
fn cloudflare_duplicate(response: &Value) -> bool {
    response["errors"].as_array().is_some_and(|errors| {
        errors.iter().any(|error| {
            error["code"].as_i64() == Some(81058)
                || error["message"]
                    .as_str()
                    .is_some_and(|message| message.contains("already exists"))
        })
    })
}
fn cloudflare_auth(
    request: reqwest::RequestBuilder,
    token: Option<&String>,
    global_key: Option<&String>,
    email: Option<&String>,
) -> reqwest::RequestBuilder {
    if let Some(token) = token {
        request.bearer_auth(token)
    } else {
        request
            .header("X-Auth-Key", global_key.expect("checked before request"))
            .header("X-Auth-Email", email.expect("checked before request"))
    }
}
async fn ensure_api(r: reqwest::Response) -> Result<()> {
    let v: Value = r.error_for_status()?.json().await?;
    if v["success"] == false {
        bail!("DNS API failed: {v}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_sub_uses_explicit_zone_for_multilevel_suffixes() {
        let (root, sub) = root_sub("_acme-challenge.api.example.co.uk", Some("example.co.uk"));
        assert_eq!(root, "example.co.uk");
        assert_eq!(sub, "api");
    }

    #[test]
    fn root_sub_handles_default_apex() {
        let (root, sub) = root_sub("_acme-challenge.example.com", None);
        assert_eq!(root, "example.com");
        assert_eq!(sub, "@");
    }

    #[test]
    fn zone_candidates_support_multilevel_public_suffixes() {
        assert_eq!(
            zone_candidates("_acme-challenge.api.example.com.cn"),
            ["api.example.com.cn", "example.com.cn", "com.cn"]
        );
    }

    #[test]
    fn cloudflare_duplicate_is_idempotent() {
        assert!(cloudflare_duplicate(&json!({"errors":[{"code":81058}]})));
        assert!(cloudflare_duplicate(
            &json!({"errors":[{"message":"The record already exists."}]})
        ));
        assert!(!cloudflare_duplicate(&json!({"errors":[{"code":10000}]})));
    }

    #[test]
    fn cloudflare_auth_supports_token_and_global_key() {
        crate::crypto::init_tls();
        let client = reqwest::Client::new();
        let token = "token".to_string();
        let request = cloudflare_auth(client.get("https://example.test"), Some(&token), None, None)
            .build()
            .unwrap();
        assert_eq!(request.headers()["authorization"], "Bearer token");
        let key = "global-key".to_string();
        let email = "user@example.test".to_string();
        let request = cloudflare_auth(
            client.get("https://example.test"),
            None,
            Some(&key),
            Some(&email),
        )
        .build()
        .unwrap();
        assert_eq!(request.headers()["x-auth-key"], "global-key");
        assert_eq!(request.headers()["x-auth-email"], "user@example.test");
    }
}
