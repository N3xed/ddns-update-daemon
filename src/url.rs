use std::collections::HashMap;

use anyhow::Result;
use rupnp::http::{HeaderMap, HeaderValue};
use serde::Deserialize;

use crate::replace_placehoders;

#[derive(Debug, serde::Deserialize, Clone)]
pub struct Url {
    /// The method used for the update request. Defaults to `get`.
    #[serde(default)]
    method: HttpMethod,
    /// The url to send the update request to, fields `{ipv4}` and `{ipv6}`
    /// will get replaced by the IPv4 and IPv6 address that was detected.
    url: String,

    #[serde(default)]
    /// Additional headers to send, fields `{ipv4}` and `{ipv6}` will be replaced
    /// with the detected IPs in the header values.
    #[serde(deserialize_with = "deserialize_headermap")]
    headers: HeaderMap<HeaderValue>,
    /// The body of the request, if the request supports a body.
    /// Fields `{ipv4}` and `{ipv6}` will again be replaced by the detected IPs.
    #[serde(default)]
    body: Option<String>,

    #[serde(skip)]
    updated: bool,
}

pub fn deserialize_headermap<'a, D>(de: D) -> Result<HeaderMap<HeaderValue>, D::Error>
where
    D: serde::Deserializer<'a>,
{
    let headers = HashMap::<String, String>::deserialize(de)?;
    let headermap = HeaderMap::<HeaderValue>::try_from(&headers);
    match headermap {
        Ok(m) => Ok(m),
        Err(err) => Err(serde::de::Error::custom(format!("{err}"))),
    }
}

impl Url {
    pub async fn update(
        &mut self,
        next_ipv4: &str,
        next_ipv6: &str,
        ip_changed: bool,
        client: &reqwest::Client,
    ) -> Result<()> {
        let res = self
            .update_inner(next_ipv4, next_ipv6, ip_changed, client)
            .await;
        self.updated = res.is_ok();
        res
    }

    #[inline]
    async fn update_inner(
        &mut self,
        next_ipv4: &str,
        next_ipv6: &str,
        ip_changed: bool,
        client: &reqwest::Client,
    ) -> Result<()> {
        if !ip_changed && self.updated {
            return Ok(());
        }
        let url = replace_placehoders(&self.url, next_ipv4, next_ipv6);
        let mut builder = client.request(self.method.into(), url);
        if !self.headers.is_empty() {
            let mut headers = self.headers.clone();

            for v in headers.values_mut() {
                // Safety: This is always safe because the original headers are parsed as
                // a hashmap of strings.
                let s = unsafe { std::str::from_utf8_unchecked(v.as_bytes()) };
                let s = replace_placehoders(s, next_ipv4, next_ipv6);
                *v = HeaderValue::from_str(&s).expect("always only visible ASCII");
            }
            builder = builder.headers(headers);
        }
        if let Some(body) = &self.body {
            let body = replace_placehoders(body, next_ipv4, next_ipv6);
            builder = builder.body(body);
        }

        let resp = client.execute(builder.build()?).await?;
        log::debug!("server responded with {resp:?}");
        resp.error_for_status()?;
        Ok(())
    }

    pub fn name(&self) -> String {
        if let Ok(url) = reqwest::Url::parse(&replace_placehoders(&self.url, "", "")) {
            url.host_str().unwrap_or("").to_owned()
        } else {
            "invalid url".into()
        }
    }
}

#[derive(Debug, serde::Deserialize, PartialEq, Eq, Clone, Copy, Default)]
#[serde(rename_all = "lowercase")]
pub enum HttpMethod {
    #[default]
    Get,
    Post,
    Put,
    Delete,
    Head,
    Trace,
    Connect,
    Patch,
    Options,
}

impl From<HttpMethod> for reqwest::Method {
    fn from(value: HttpMethod) -> Self {
        match value {
            HttpMethod::Get => reqwest::Method::GET,
            HttpMethod::Post => reqwest::Method::POST,
            HttpMethod::Put => reqwest::Method::PUT,
            HttpMethod::Delete => reqwest::Method::DELETE,
            HttpMethod::Head => reqwest::Method::HEAD,
            HttpMethod::Trace => reqwest::Method::TRACE,
            HttpMethod::Connect => reqwest::Method::CONNECT,
            HttpMethod::Patch => reqwest::Method::PATCH,
            HttpMethod::Options => reqwest::Method::OPTIONS,
        }
    }
}
