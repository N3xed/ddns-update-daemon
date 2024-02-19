use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use futures::pin_mut;
use futures::prelude::*;
use rupnp::ssdp::URN;

use crate::config::DNSRecordType;

#[derive(clap::Parser)]
struct Args {
    /// The path to the `config.toml` file.
    /// If unset, `<current work dir>/config.toml` or `<exe dir>/config.toml` will be used
    /// (in that order).
    config: Option<PathBuf>,
}

pub mod config {
    use std::path::Path;

    use crate::cloudflare_api;

    #[derive(Debug, serde::Deserialize)]
    pub struct Config {
        /// Optional router IP address that will be used to query the external IP address using UPnP.
        pub router_ip: Option<std::net::IpAddr>,
        /// The interval in minutes to check if the external ip changed.
        pub interval: u64,
        /// The cloudflare DNS records to update.
        #[serde(default)]
        pub cloudflare: Option<Cloudflare>,
    }
    impl Config {
        pub fn print(&self, path: &Path) {
            log::info!("Found config at '{}'", path.display());
            if let Some(ip) = &self.router_ip {
                if ip.is_loopback() {
                    log::info!("Foud loopback as router_ip, watching local IP address instead.")
                } else {
                    log::info!("Using configured router_ip '{ip}'")
                }
            } else {
                log::info!("No router_ip configured, detecting from the network.")
            }
            if let Some(cf) = &self.cloudflare {
                log::info!(
                    "Found updater for cloudflare: {} DNS record(s)",
                    cf.records.len()
                );
            }
        }
    }

    #[derive(Debug, serde::Deserialize)]
    pub struct Cloudflare {
        /// Authentification for the cloudflaare API.
        #[serde(flatten)]
        pub auth: cloudflare_api::Auth,
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
        Debug,
        serde::Deserialize,
        serde::Serialize,
        PartialEq,
        Eq,
        Clone,
        Copy,
        parse_display::Display,
    )]
    #[allow(clippy::upper_case_acronyms)]
    pub enum DNSRecordType {
        A,
        AAAA,
    }
}

fn check_cfg_exists(p: PathBuf) -> Result<PathBuf> {
    if p.exists() {
        Ok(p)
    } else {
        Err(anyhow!("config.toml file '{}' does not exist", p.display()))
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    simple_logger::SimpleLogger::new()
        .with_level(
            #[cfg(debug_assertions)]
            log::LevelFilter::Debug,
            #[cfg(not(debug_assertions))]
            log::LevelFilter::Info,
        )
        .env()
        .init()
        .unwrap();

    // Figure out the config path to use.
    let config_path = match args.config {
        Some(mut p) => {
            if p.is_relative() {
                if let Ok(cwd) = std::env::current_dir() {
                    p = cwd.join(p);
                }
            }

            check_cfg_exists(p)?
        }
        None => {
            let cwd_cfg = std::env::current_dir()
                .map_err(anyhow::Error::from)
                .map(|p| p.join("config.toml"))
                .and_then(check_cfg_exists);

            if let Ok(p) = cwd_cfg {
                p
            } else {
                let pd_cfg = std::env::current_exe()
                    .map_err(anyhow::Error::from)
                    .and_then(|p| {
                        let dir = p.parent().with_context(|| {
                            anyhow!("path '{}' does not have parent", p.display())
                        })?;
                        let cfg = dir.join("config.toml");
                        check_cfg_exists(cfg)
                    });

                if let Ok(p) = pd_cfg {
                    p
                } else {
                    log::info!(
                        "could not get config.toml from current work dir: {:?}",
                        cwd_cfg.unwrap_err()
                    );
                    return Err(pd_cfg
                        .unwrap_err()
                        .context(anyhow!("could not get config.toml from executable dir")));
                }
            }
        }
    };

    // Deserialize the config.
    let config: config::Config = toml::from_str(
        &std::fs::read_to_string(&config_path)
            .with_context(|| anyhow!("could not read file '{}'", config_path.display()))?,
    )
    .with_context(|| anyhow!("could not deserialize config '{}'", config_path.display()))?;

    // Print information about the config.
    config.print(&config_path);
    if config.cloudflare.is_none() {
        log::warn!("Nothing to update: no updaters defined");
        log::info!("Exiting.");
        return Ok(());
    }

    // Discover the internet gateway device to be querried.
    // let service = if config.
    let service = if config
        .router_ip
        .as_ref()
        .map(IpAddr::is_loopback)
        .unwrap_or(false)
    {
        log::info!("Watching local IP address");
        IpService::Local
    } else {
        let upnp_service = UPnPIpService::new_ip_connection_service(None).await?;
        log::info!(
            "Using router '{}' at '{}' to get external IP",
            upnp_service.router_name(),
            upnp_service.router_ip()
        );
        IpService::UPnP(upnp_service)
    };

    let interval_duration = tokio::time::Duration::from_secs(config.interval * 60);
    let mut curr_ipv4: Option<Ipv4Addr> = None;
    let mut curr_ipv6: Option<Ipv6Addr> = None;
    loop {
        let (next_ipv4, next_ipv6) = service.get_current_ips().await;
        if next_ipv4.is_none() && next_ipv6.is_none() {
            log::warn!("Both IPv4 and IPv6 unavailable, cannot update");
        } else {
            if curr_ipv4 != next_ipv4 && next_ipv4.is_some() {
                let ipv4 = next_ipv4.unwrap();

                log::info!("Detected new IPv4 address '{ipv4}', updating..");

                // Update cloudflare IPv4 DNS records.
                if let Some(cf) = &config.cloudflare {
                    for record in cf.records.iter().filter(|r| r.typ == DNSRecordType::A) {
                        let upd_record = cloudflare_api::DNSRecord {
                            name: record.name.clone(),
                            typ: record.typ,
                            content: ipv4.to_string(),
                        };

                        if let Err(err) = cloudflare_api::update_dns_record(&cf.auth, &upd_record)
                            .await
                            .with_context(|| {
                                anyhow!("could not update cloudflare DNS record '{}'", &record.name)
                            })
                        {
                            log::error!("{err:?}");
                        }
                    }
                }

                curr_ipv4 = Some(ipv4);
            }

            if curr_ipv6 != next_ipv6 && next_ipv6.is_some() {
                let ipv6 = next_ipv6.unwrap();

                log::info!("Detected new IPv6 address '{ipv6}', updating..");

                // Update cloudflare IPv6 DNS records.
                if let Some(cf) = &config.cloudflare {
                    for record in cf.records.iter().filter(|r| r.typ == DNSRecordType::AAAA) {
                        let upd_record = cloudflare_api::DNSRecord {
                            name: record.name.clone(),
                            typ: record.typ,
                            content: ipv6.to_string(),
                        };

                        if let Err(err) = cloudflare_api::update_dns_record(&cf.auth, &upd_record)
                            .await
                            .with_context(|| {
                                anyhow!("could not update cloudflare DNS record '{}'", &record.name)
                            })
                        {
                            log::error!("{err:?}");
                        }
                    }
                }

                curr_ipv6 = Some(ipv6);
            }
        }

        tokio::time::sleep(interval_duration).await;
    }
}

enum IpService {
    UPnP(UPnPIpService),
    Local,
}

impl IpService {
    async fn get_current_ips(&self) -> (Option<Ipv4Addr>, Option<Ipv6Addr>) {
        match self {
            IpService::UPnP(s) => s.get_current_ips().await,
            IpService::Local => get_current_local_ips(),
        }
    }
}

/// A service that queries the external IP address from the router using UPnP.
pub struct UPnPIpService {
    device: rupnp::Device,
    service_scpd: rupnp::scpd::SCPD,
    service: rupnp::Service,
}

impl UPnPIpService {
    pub fn router_ip(&self) -> &str {
        self.device.url().host().unwrap()
    }

    pub fn router_name(&self) -> &str {
        self.device.friendly_name()
    }

    /// Get the `WANIPConnection` service from the `InternetGatewayDevice` matching `ipaddr` using
    /// [UPnP WAN Common Interface Config](http://upnp.org/specs/gw/UPnP-gw-WANCommonInterfaceConfig-v1-Service.pdf).
    async fn new_ip_connection_service(ipaddr: Option<std::net::IpAddr>) -> Result<UPnPIpService> {
        const INTERNET_GATEWAY_DEVICE: URN =
            URN::device("schemas-upnp-org", "InternetGatewayDevice", 1);
        const WANIP_CON_SERVICE: URN = URN::service("schemas-upnp-org", "WANIPConnection", 1);
        const WAN_DEVICE: URN = URN::device("schemas-upnp-org", "WANDevice", 1);
        const WAN_CONNECTION_DEVICE: URN =
            URN::device("schemas-upnp-org", "WANConnectionDevice", 1);

        let devices = rupnp::discover(
            &rupnp::ssdp::SearchTarget::URN(INTERNET_GATEWAY_DEVICE),
            Duration::from_secs(120),
        )
        .await?;
        pin_mut!(devices);

        let gateway = loop {
            let gateway = match devices.try_next().await? {
                Some(d) => d,
                None => bail!("could not find internet gateway device"),
            };

            if let Some(gateway_ip) = &ipaddr {
                if let Some(mut host) = gateway.url().host() {
                    host = host.strip_prefix('[').unwrap_or(host);
                    host = host.strip_suffix(']').unwrap_or(host);
                    let device_ip: std::net::IpAddr = match host.parse() {
                        Ok(s) => s,
                        Err(err) => {
                            let uri = gateway.url();
                            let device_name = gateway.friendly_name();
                            log::info!("Uri '{uri}' of discovered gateway '{device_name}' is not a valid IP address: {err:?}");
                            continue;
                        }
                    };

                    if device_ip == *gateway_ip {
                        break gateway;
                    }
                }
            } else {
                break gateway;
            }
        };

        let device = gateway
            .devices_iter()
            .find(|d| *d.device_type() == WAN_DEVICE)
            .with_context(|| anyhow!("could not find WAN device"))?
            .devices_iter()
            .find(|d| *d.device_type() == WAN_CONNECTION_DEVICE)
            .with_context(|| anyhow!("could not find WAN connection device"))?;

        let service = device
            .services_iter()
            .find(|d| *d.service_type() == WANIP_CON_SERVICE)
            .with_context(|| anyhow!("could not find WAN IP connection service"))?;

        let service_scpd = service.scpd(gateway.url()).await?;

        Ok(UPnPIpService {
            service: service.clone(),
            service_scpd,
            device: gateway,
        })
    }

    /// Get the external ip address.
    pub async fn get_current_external_ip(&self) -> Result<IpAddr> {
        const ACTION: &str = "GetExternalIPAddress";
        const IPV4_ADDR_VAR: &str = "NewExternalIPAddress";

        let response = match self.service.action(self.device.url(), ACTION, "").await {
            Err(err) => return Err(anyhow!(err).context(format!("{ACTION} failed"))),
            Ok(r) => r,
        };

        let ip_addr_str = response
            .get(IPV4_ADDR_VAR)
            .with_context(|| anyhow!("{ACTION} gave empty response"))?;

        Ok(ip_addr_str.parse()?)
    }

    /// Get the external IPV6 address. Currently only supported on FRITZ!Box with the
    /// `X_AVM_DE_GetExternalIPv6Address` action.
    pub async fn get_current_external_ipv6(&self) -> Result<Option<Ipv6Addr>> {
        const ACTION: &str = "X_AVM_DE_GetExternalIPv6Address";
        const IPV6_ADDR_VAR: &str = "NewExternalIPv6Address";
        const VALID_LIFETIME_VAR: &str = "NewValidLifetime";

        if self
            .service_scpd
            .actions()
            .iter()
            .any(|act| act.name() == ACTION)
        {
            return Ok(None);
        }

        let response = match self.service.action(self.device.url(), ACTION, "").await {
            Err(err) => return Err(anyhow!(err).context(format!("{ACTION} failed"))),
            Ok(r) => r,
        };

        let valid_lifetime = match response.get(VALID_LIFETIME_VAR) {
            None => return Ok(None),
            Some(v) => v,
        };
        let ipv6_addr = match response.get(IPV6_ADDR_VAR) {
            None => return Ok(None),
            Some(v) => v,
        };

        let valid_lifetime: u64 = valid_lifetime.parse()?;
        if valid_lifetime == 0 {
            Ok(None)
        } else {
            Ok(Some(ipv6_addr.parse()?))
        }
    }

    async fn get_current_ips(&self) -> (Option<Ipv4Addr>, Option<Ipv6Addr>) {
        let (ipv4, ipv6) = match self.get_current_external_ip().await {
            Ok(IpAddr::V4(ip)) => (Some(ip), None),
            Ok(IpAddr::V6(ip)) => (None, Some(ip)),
            Err(err) => {
                log::error!("{err:?}");
                (None, None)
            }
        };
        let ipv6 = if let Some(_) = ipv6 {
            ipv6
        } else {
            match self.get_current_external_ipv6().await {
                Ok(ip) => ip,
                Err(err) => {
                    log::error!("{err:?}");
                    None
                }
            }
        };

        (ipv4, ipv6)
    }
}

fn get_current_local_ips() -> (Option<Ipv4Addr>, Option<Ipv6Addr>) {
    let (ipv4, ipv6) = match local_ip_address::local_ip() {
        Ok(IpAddr::V4(ip)) => (Some(ip), None),
        Ok(IpAddr::V6(ip)) => (None, Some(ip)),
        Err(err) => {
            log::error!("{err:?}");
            (None, None)
        }
    };
    let ipv6 = if let Some(_) = ipv6 {
        ipv6
    } else {
        match local_ip_address::local_ipv6() {
            Ok(IpAddr::V6(ip)) => Some(ip),
            Ok(IpAddr::V4(_)) => None,
            Err(err) => {
                log::error!("{err:?}");
                None
            }
        }
    };
    (ipv4, ipv6)
}

mod cloudflare_api {
    use anyhow::{anyhow, bail, Context, Result};
    use reqwest::Client;

    use crate::DNSRecordType;

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

    pub async fn update_dns_record(auth: &Auth, dns_record: &DNSRecord) -> Result<()> {
        let Auth { zone_id, api_token } = auth;

        let (client, request) = Client::new()
            .get(format!(
                "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
            ))
            .bearer_auth(api_token)
            .query(&[
                ("name", &encode_punycode(&dns_record.name)?),
                ("type", &dns_record.typ.to_string()),
            ])
            .build_split();
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
}
