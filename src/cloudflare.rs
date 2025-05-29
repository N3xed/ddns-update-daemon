use std::net::IpAddr;

use anyhow::{Context, Result, anyhow, bail};
use reqwest::Client;

#[derive(Debug, serde::Deserialize)]
pub struct Cloudflare {
    /// Authentification for the cloudflare API.
    #[serde(flatten)]
    pub auth: Auth,
    /// Cloudflare DNS records to update.
    pub records: Vec<CloudflareDNSRecord>,
}

#[derive(Debug, serde::Deserialize, Clone)]
pub struct CloudflareDNSRecord {
    /// The name of the DNS record to update.
    pub name: String,
    /// The DNS record type, currently supports `A` or `AAAA`.
    #[serde(rename = "type")]
    pub typ: DNSRecordType,
}

#[derive(
    Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq, Clone, Copy, parse_display::Display,
)]
#[allow(clippy::upper_case_acronyms)]
pub enum DNSRecordType {
    /// IPv4.
    A,
    /// IPv6.
    AAAA,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct Auth {
    /// The zone ID of the cloudflare site.
    pub zone_id: String,
    /// The cloudflare API access token.
    pub api_token: String,
}

#[derive(Debug, serde::Serialize)]
pub struct DNSRecord {
    pub content: String,
    #[serde(serialize_with = "serialize_punycode")]
    pub name: String,
    #[serde(rename = "type")]
    pub typ: DNSRecordType,
}

pub fn encode_punycode(val: &str) -> Result<String> {
    idna::domain_to_ascii(val).with_context(|| anyhow!("could not encode '{val}' in punycode"))
}

pub fn serialize_punycode<S>(val: &str, ser: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let s = encode_punycode(val).map_err(|err| serde::ser::Error::custom(format!("{err}")))?;
    ser.serialize_str(&s)
}

#[derive(Debug, serde::Deserialize)]
#[allow(dead_code)]
struct DnsApiResponse {
    #[serde(default)]
    success: bool,
    #[serde(default)]
    errors: Vec<Message>,
    #[serde(default)]
    messages: Vec<Message>,
    #[serde(default)]
    result: Option<DnsApiResult>,
}

#[derive(Debug, serde::Deserialize)]
#[allow(dead_code)]
struct Message {
    code: i64,
    message: String,
}

#[derive(serde::Deserialize, Debug)]
#[serde(untagged)]
enum DnsApiResult {
    List(Vec<ListRecordsResult>),
    Patch {},
}

#[derive(Debug, serde::Deserialize)]
struct ListRecordsResult {
    id: String,
}

async fn get_dns_record_id(client: &Client, auth: &Auth, dns_record: &DNSRecord) -> Result<String> {
    let Auth { zone_id, api_token } = auth;

    let request = client
        .get(format!(
            "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
        ))
        .bearer_auth(api_token)
        .query(&[
            ("name", &encode_punycode(&dns_record.name)?),
            ("type", &dns_record.typ.to_string()),
        ])
        .build();
    let resp = client.execute(request?).await?;
    let data = check_reponse(resp, None)
        .await?
        .ok_or_else(|| anyhow!("empty cloudflare response"))?;

    let ListRecordsResult { id } = match data.result {
        Some(DnsApiResult::List(mut res)) if !res.is_empty() => res.swap_remove(0),
        _ => {
            bail!(
                "no DNS records matched name '{}' and type '{}'",
                dns_record.name,
                dns_record.typ
            );
        }
    };
    Ok(id)
}

async fn update_dns_record(
    client: &Client,
    auth: &Auth,
    dns_record: &DNSRecord,
    id: &str,
) -> Result<()> {
    let Auth { zone_id, api_token } = auth;

    let resp = client
        .patch(format!(
            "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{id}"
        ))
        .bearer_auth(api_token)
        .json(&dns_record)
        .send()
        .await?;

    check_reponse(resp, Some(dns_record)).await?;
    Ok(())
}

async fn check_reponse(
    resp: reqwest::Response,
    dns_record: Option<&DNSRecord>,
) -> Result<Option<DnsApiResponse>> {
    let resp_status = resp.status();
    let res_err = resp.error_for_status_ref().err();
    let data: Option<DnsApiResponse> = match resp.json().await {
        Err(err) => {
            return Err(anyhow::Error::from(err).context("could not get cloudflare response"));
        }
        Ok(d) => d,
    };

    if !data.as_ref().map(|d| d.success).unwrap_or(false) || res_err.is_some() {
        let error = if let Some(err) = res_err {
            anyhow::Error::new(err)
        } else {
            anyhow!("cloudflare API call failed")
        };
        let mut err_text = String::new();
        if let Some(dns_record) = dns_record {
            err_text.push_str(&format!(
                "when sending data:\n{}",
                serde_json::to_string_pretty(&dns_record).unwrap()
            ));
        }
        if let Some(data) = data {
            err_text.push_str(&format!(
                "\ncloudflare responded with {resp_status}: {data:#?}"
            ))
        }
        return Err(anyhow!(err_text).context(error));
    }
    Ok(data)
}

pub struct CloudflareUpdater {
    record: CloudflareDNSRecord,
    updated: bool,
    record_id: Option<String>,
}

impl CloudflareUpdater {
    pub fn new(record: CloudflareDNSRecord) -> Self {
        Self {
            record,
            updated: false,
            record_id: None,
        }
    }

    pub fn is_ipv4(&self) -> bool {
        matches!(self.record.typ, DNSRecordType::A)
    }

    pub fn name(&self) -> &str {
        &self.record.name
    }

    pub async fn update(
        &mut self,
        auth: &Auth,
        ip: IpAddr,
        new_ip: bool,
        client: &Client,
    ) -> Result<()> {
        let res = self.update_inner(auth, ip, new_ip, client).await;
        self.updated = res.is_ok();
        res
    }

    #[inline]
    async fn update_inner(
        &mut self,
        auth: &Auth,
        ip: IpAddr,
        ip_changed: bool,
        client: &reqwest::Client,
    ) -> Result<()> {
        let dns_record = DNSRecord {
            name: self.record.name.clone(),
            typ: self.record.typ,
            content: ip.to_string(),
        };

        if !ip_changed && self.updated {
            return Ok(());
        }

        let id = match &self.record_id {
            Some(id) => id,
            None => {
                let id = get_dns_record_id(client, auth, &dns_record)
                    .await
                    .with_context(|| anyhow!("failed to get DNS record ID from cloudflare"))?;

                self.record_id = Some(id);
                self.record_id.as_ref().unwrap()
            }
        };

        update_dns_record(client, auth, &dns_record, id.as_ref())
            .await
            .with_context(|| {
                self.record_id = None;
                anyhow!(
                    "could not update cloudflare DNS record '{}'",
                    &self.record.name
                )
            })?;

        Ok(())
    }
}
