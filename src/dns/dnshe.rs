use super::*;
use reqwest::{StatusCode, header::HeaderValue};

#[cfg(test)]
mod tests;

pub(super) const API: &str = "https://api005.dnshe.com/index.php";
const PAGE_SIZE: usize = 500;
const MAX_PAGES: usize = 100;
const API_KEY: &str = "DNSHE_API_KEY";
const API_SECRET: &str = "DNSHE_API_SECRET";

pub(super) fn validate_credentials(vars: &HashMap<String, String>) -> Result<()> {
    for key in [API_KEY, API_SECRET] {
        let value = vars.get(key).map(String::as_str).unwrap_or_default();
        anyhow::ensure!(
            !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_graphic()),
            "{key} must be a nonempty DNSHE credential without whitespace"
        );
    }
    Ok(())
}

impl Dns {
    pub(super) async fn dnshe(&self, add: bool, name: &str, value: &str, api: &str) -> Result<()> {
        let name = dns_name(name);
        let (zone, zone_id) = self.dnshe_zone(api, &name).await?;
        let relative = relative_name(&name, &zone).context("challenge is outside DNSHE zone")?;
        let reply = self
            .dnshe_request(
                api,
                "dns_records",
                "list",
                &[("subdomain_id", zone_id.to_string())],
                None,
            )
            .await?;
        let records = reply["records"]
            .as_array()
            .context("DNSHE response has no record array")?;
        let mut matched_ids = std::collections::BTreeSet::new();
        for record in records {
            if record["type"]
                .as_str()
                .is_some_and(|kind| kind.eq_ignore_ascii_case("TXT"))
                && record["name"].as_str().is_some_and(|record_name| {
                    let record_name = dns_name(record_name);
                    record_name == name
                        || record_name == relative
                        || (record_name.is_empty() && relative == "@")
                })
                && record["content"].as_str().is_some_and(|content| {
                    content == value
                        || content.strip_prefix('"').and_then(|s| s.strip_suffix('"'))
                            == Some(value)
                })
            {
                matched_ids.insert(
                    positive_id(&record["id"]).context("DNSHE TXT record has no valid id")?,
                );
            }
        }

        if add && matched_ids.is_empty() {
            self.dnshe_request(
                api,
                "dns_records",
                "create",
                &[],
                Some(json!({
                    "subdomain_id": zone_id, "type": "TXT", "name": relative, "content": value,
                })),
            )
            .await?;
        } else if !add {
            let mut failures = Vec::new();
            for id in matched_ids {
                if let Err(error) = self
                    .dnshe_request(api, "dns_records", "delete", &[], Some(json!({"id": id})))
                    .await
                {
                    failures.push(error.to_string());
                }
            }
            anyhow::ensure!(
                failures.is_empty(),
                "DNSHE TXT cleanup failed: {}",
                failures.join(", ")
            );
        }
        Ok(())
    }

    async fn dnshe_zone(&self, api: &str, name: &str) -> Result<(String, u64)> {
        let mut best: Option<(String, u64, bool)> = None;
        for page in 1..=MAX_PAGES {
            let reply = self
                .dnshe_request(
                    api,
                    "subdomains",
                    "list",
                    &[
                        ("page", page.to_string()),
                        ("per_page", PAGE_SIZE.to_string()),
                        ("fields", "id,full_domain,status".to_string()),
                    ],
                    None,
                )
                .await?;
            let domains = reply["subdomains"]
                .as_array()
                .context("DNSHE response has no domain array")?;
            for domain in domains {
                let Some(zone) = domain["full_domain"].as_str().map(dns_name) else {
                    continue;
                };
                if zone.is_empty()
                    || best
                        .as_ref()
                        .is_some_and(|(old, _, _)| old.len() >= zone.len())
                {
                    continue;
                }
                if relative_name(name, &zone).is_some() {
                    let id = positive_id(&domain["id"])
                        .context("DNSHE managed domain has no valid id")?;
                    let status = domain["status"].as_str().unwrap_or_default().trim();
                    let usable = status.eq_ignore_ascii_case("active")
                        || status.eq_ignore_ascii_case("registered");
                    best = Some((zone, id, usable));
                }
            }
            let more = reply
                .pointer("/pagination/has_more")
                .and_then(Value::as_bool)
                .unwrap_or(domains.len() >= PAGE_SIZE);
            if !more {
                let (zone, id, usable) =
                    best.context("DNSHE account has no managed domain for the challenge")?;
                anyhow::ensure!(usable, "DNSHE managed domain {zone} is inactive");
                return Ok((zone, id));
            }
            anyhow::ensure!(
                !domains.is_empty(),
                "DNSHE domain pagination returned an empty page with more results"
            );
        }
        bail!("DNSHE domain pagination exceeded {MAX_PAGES} pages")
    }

    async fn dnshe_request(
        &self,
        api: &str,
        endpoint: &str,
        action: &str,
        query: &[(&str, String)],
        body: Option<Value>,
    ) -> Result<Value> {
        let header = |key| -> Result<HeaderValue> {
            let mut value = HeaderValue::from_str(&self.vars[key])
                .context("invalid DNSHE credential header")?;
            value.set_sensitive(true);
            Ok(value)
        };
        let request = match body {
            Some(body) => self.client.post(api).json(&body),
            None => self.client.get(api),
        };
        let response = request
            .query(&[
                ("m", "domain_hub"),
                ("endpoint", endpoint),
                ("action", action),
            ])
            .query(query)
            .header("Accept", "application/json")
            .header("X-API-Key", header(API_KEY)?)
            .header("X-API-Secret", header(API_SECRET)?)
            .send()
            .await
            .map_err(|_| anyhow::anyhow!("DNSHE {endpoint}/{action} request failed"))?;
        let status = response.status();
        let data: Value = response.json().await.map_err(|_| {
            anyhow::anyhow!("DNSHE {endpoint}/{action} returned invalid JSON (HTTP {status})")
        })?;
        if status.is_success() && data["success"].as_bool() == Some(true) {
            return Ok(data);
        }
        let reason = match data["error_code"].as_str() {
            Some("dns_record_not_found")
                if action == "delete" && status == StatusCode::NOT_FOUND =>
            {
                return Ok(data);
            }
            Some("auth_invalid_credentials") => "invalid API Key or API Secret",
            Some("auth_ip_not_allowed") => "outbound IP is not allowed",
            Some("external_dns_delegated") => "managed domain uses external nameservers",
            Some("quota_exceeded") => "quota exceeded",
            Some("rate_limit_exceeded") => "rate limit exceeded",
            _ => "API rejected the request",
        };
        bail!("DNSHE {endpoint}/{action} failed (HTTP {status}): {reason}")
    }
}

fn dns_name(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

fn relative_name<'a>(name: &'a str, zone: &str) -> Option<&'a str> {
    if name == zone {
        Some("@")
    } else {
        name.strip_suffix(zone)?.strip_suffix('.')
    }
}

fn positive_id(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str()?.parse().ok())
        .filter(|id| *id > 0)
}
