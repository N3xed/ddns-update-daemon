use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use futures::pin_mut;
use futures::prelude::*;
use rupnp::ssdp::URN;

mod cloudflare;
mod url;

/// A daemon for updating DynDNS services when the IP address changes.
///
/// Supports cloudflare, URL requests, and running programs on IP change.
/// Please see https://github.com/N3xed/ddns-update-daemon for the configuration format.
#[derive(clap::Parser)]
#[command(version, about)]
struct Args {
    /// The path to the `config.toml` file.
    config: PathBuf,
    /// Enable verbose logging.
    #[clap(short, long)]
    verbose: bool,
}

pub mod config {
    use std::path::Path;

    use crate::{cloudflare, url};

    #[derive(Debug, serde::Deserialize)]
    pub struct Config {
        /// Optional router IP address that will be used to query the external IP address using UPnP.
        pub router_ip: Option<std::net::IpAddr>,
        /// The interval in minutes to check if the IP address changed.
        /// May be fractional (i.e. `0.5`).
        pub interval: f64,
        /// The cloudflare DNS records to update.
        #[serde(default)]
        pub cloudflare: Option<cloudflare::Cloudflare>,
        /// Custom urls to send update requests to.
        #[serde(default)]
        pub urls: Vec<url::Url>,
        /// Run one or more programs when new IP(s) are detected.
        #[serde(default)]
        pub runs: Vec<Run>,
    }
    impl Config {
        pub fn print(&self, path: &Path) {
            log::info!("Found config at '{}'", path.display());
            if let Some(ip) = &self.router_ip {
                if ip.is_loopback() {
                    log::info!("Found loopback as router_ip, watching local IP address instead.")
                } else {
                    log::info!("Using configured router_ip '{ip}'.")
                }
            } else {
                log::info!("No router_ip configured, detecting from the network.")
            }
            if let Some(cf) = &self.cloudflare {
                log::info!(
                    "Found updater for cloudflare: {} DNS record(s).",
                    cf.records.len()
                );
            }
            if !self.urls.is_empty() {
                log::info!("Found updater for {} urls.", self.urls.len());
            }
            if !self.runs.is_empty() {
                log::info!(
                    "Found {} program(s) to be executed on IP address change.",
                    self.runs.len()
                );
            }
        }
    }

    #[derive(Debug, serde::Deserialize, Clone)]
    pub struct Run {
        /// The program to run and command line arguments,
        /// `{ipv4}` and `{ipv6}` will be replaced with the detected IPs.
        pub cmd: Vec<String>,
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    simple_logger::SimpleLogger::new()
        .with_level(if args.verbose {
            log::LevelFilter::Debug
        } else {
            log::LevelFilter::Info
        })
        .init()
        .unwrap();

    // Figure out the config path to use.
    let config_path = {
        let cfg = match std::env::current_dir() {
            Ok(cwd) if args.config.is_relative() => cwd.join(args.config),
            _ => args.config,
        };

        if cfg.exists() {
            Ok(cfg)
        } else {
            Err(anyhow!(
                "config.toml file '{}' does not exist",
                cfg.display()
            ))
        }
    }?;

    // Deserialize the config.
    let config: config::Config = toml::from_str(
        &std::fs::read_to_string(&config_path)
            .with_context(|| anyhow!("could not read file '{}'", config_path.display()))?,
    )
    .with_context(|| anyhow!("could not deserialize config '{}'", config_path.display()))?;

    // Print information about the config.
    config.print(&config_path);
    if config.cloudflare.is_none() && config.urls.is_empty() && config.runs.is_empty() {
        log::warn!("Nothing to update: no updaters defined");
        log::info!("Exiting.");
        return Ok(());
    }

    let config::Config {
        router_ip,
        interval,
        cloudflare: cf,
        mut urls,
        runs,
    } = config;

    // Discover the internet gateway device to be querried or watch the local ip
    // if loopback.
    log::info!("Discovering internet gateway..");
    let mut service = IpService::new(router_ip, true).await?;

    let (cf_auth, mut cf_updaters) = if let Some(cf) = cf {
        let updaters = cf
            .records
            .into_iter()
            .map(cloudflare::CloudflareUpdater::new)
            .collect();
        (Some(cf.auth), updaters)
    } else {
        (None, Vec::new())
    };

    let interval = (interval * 60.0).round();
    anyhow::ensure!(
        interval >= 0.0 && interval.is_finite() && interval <= u64::MAX as f64,
        "interval * 60 ({interval}) must be positive and less than `2^64 - 1`"
    );
    log::info!("Using {interval} seconds interval.");

    let interval = tokio::time::Duration::from_secs(interval as u64);
    let mut curr_ipv4: Option<Ipv4Addr> = None;
    let mut curr_ipv6: Option<Ipv6Addr> = None;
    loop {
        let (next_ipv4, next_ipv6) = match service.get_current_ips().await {
            Ok(v) => v,
            Err(_) => {
                log::info!("UPnP request failed; rediscovering internet gateway..");
                // Try to recreate the IpService, since the previous call errored.
                let new_service = IpService::new(config.router_ip, false).await;
                if let Ok(new_service) = new_service {
                    service = new_service;
                }
                (None, None)
            }
        };

        let ipv4_changed = curr_ipv4 != next_ipv4;
        let ipv6_changed = curr_ipv6 != next_ipv6;
        let ip_changed = ipv4_changed || ipv6_changed;
        match (&next_ipv4, &next_ipv6) {
            (None, None) => {
                log::warn!("Both IPv4 and IPv6 unavailable.");
            }
            (Some(ipv4), None) if ip_changed => {
                log::info!("IP address changed: IPv4={ipv4}, IPv6=unavailable. Updating..");
            }
            (None, Some(ipv6)) if ip_changed => {
                log::info!("IP address changed: IPv4=unavailable, IPv6={ipv6}. Updating..");
            }
            (Some(ipv4), Some(ipv6)) if ip_changed => {
                log::info!("IP address changed: IPv4={ipv4}, IPv6={ipv6}. Updating..");
            }
            (ipv4, ipv6) => {
                log::debug!("IP address no change:  IPv4={ipv4:?}, IPv6={ipv6:?}");
            }
        }

        if cf_auth.is_some() || !urls.is_empty() {
            let client = reqwest::Client::builder().build();
            match client {
                Ok(client) => {
                    // Update cloudflare.
                    if let Some(cf_auth) = &cf_auth {
                        for updater in &mut cf_updaters {
                            let (ip, new_ip) = if updater.is_ipv4() {
                                // Do not update if no IP is available.
                                let Some(ipv4) = next_ipv4 else { continue };
                                (IpAddr::V4(ipv4), ipv4_changed)
                            } else {
                                // Do not update if no IP is available.
                                let Some(ipv6) = next_ipv6 else { continue };
                                (IpAddr::V6(ipv6), ipv6_changed)
                            };

                            log::debug!("Updating cloudflare DNS record '{}'", updater.name());
                            let res = updater
                                .update(cf_auth, ip, new_ip, &client)
                                .await
                                .with_context(|| {
                                    anyhow!(
                                        "could not update cloudflare DNS record '{}'",
                                        updater.name()
                                    )
                                });

                            if let Err(err) = res {
                                log::error!("{:?}", err);
                            }
                        }
                    }

                    if !urls.is_empty() {
                        let ipv4 = next_ipv4
                            .as_ref()
                            .map(ToString::to_string)
                            .unwrap_or_default();
                        let ipv6 = next_ipv6
                            .as_ref()
                            .map(ToString::to_string)
                            .unwrap_or_default();

                        // Update urls.
                        for (i, url) in urls.iter_mut().enumerate() {
                            log::debug!("Updating url {i} ('{}')", url.name());
                            let res = url
                                .update(&ipv4, &ipv6, ip_changed, &client)
                                .await
                                .with_context(|| {
                                    anyhow!("updating url {i} ('{}') failed", url.name())
                                });

                            if let Err(err) = res {
                                log::error!("{:?}", err);
                            }
                        }
                    }
                }
                Err(err) => {
                    log::error!("Failed to initialize HTTP request backend: {:?}", err);
                }
            }
        }

        if ip_changed {
            let ipv4 = next_ipv4
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_default();
            let ipv6 = next_ipv6
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_default();

            let mut handles = Vec::with_capacity(runs.len());
            for run in &runs {
                if run.cmd.is_empty() {
                    continue;
                }
                let args: Vec<String> = run
                    .cmd
                    .iter()
                    .skip(1)
                    .map(|arg| replace_placehoders(arg, &ipv4, &ipv6))
                    .collect();
                match std::process::Command::new(&run.cmd[0]).args(args).spawn() {
                    Err(err) => {
                        log::error!("Could not launch '{}': {:?}", run.cmd[0], err);
                    }
                    Ok(h) => handles.push(h),
                }
            }

            for mut h in handles {
                // Ignore the command result.
                let _ = h.wait();
            }
        }

        curr_ipv4 = next_ipv4;
        curr_ipv6 = next_ipv6;
        tokio::time::sleep(interval).await;
    }
}

pub fn replace_placehoders(s: &str, ipv4: &str, ipv6: &str) -> String {
    let s = s.replace("{ipv4}", ipv4);
    s.replace("{ipv6}", ipv6)
}

enum IpService {
    UPnP(UPnPIpService),
    Local,
}

impl IpService {
    async fn get_current_ips(&self) -> Result<(Option<Ipv4Addr>, Option<Ipv6Addr>), ()> {
        match self {
            IpService::UPnP(s) => s.get_current_ips().await,
            IpService::Local => get_current_local_ips(),
        }
    }

    /// Create an IP address service.
    /// Query local IP address if `ipaddr` is loopback otherwise use UPnP to
    /// query the router's given by `ipaddr` or the first discovered.
    async fn new(ipaddr: Option<std::net::IpAddr>, verbose: bool) -> Result<Self> {
        if ipaddr.as_ref().map(IpAddr::is_loopback).unwrap_or(false) {
            if verbose {
                log::info!("Watching the local IP address.");
            }
            Ok(IpService::Local)
        } else {
            let upnp_service = UPnPIpService::new_ip_connection_service(ipaddr).await?;
            log::info!(
                "Using router '{}' at '{}' to get the external IP address.",
                upnp_service.router_name(),
                upnp_service.router_ip()
            );
            Ok(IpService::UPnP(upnp_service))
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

            log::debug!(
                "Found gateway '{}' at '{}'",
                gateway.friendly_name(),
                gateway.url()
            );
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
    pub async fn get_current_external_ip(&self) -> Result<Option<IpAddr>> {
        const ACTION: &str = "GetExternalIPAddress";
        const IPV4_ADDR_VAR: &str = "NewExternalIPAddress";

        let response = match self.service.action(self.device.url(), ACTION, "").await {
            Err(err) => return Err(anyhow!(err).context(format!("{ACTION} failed"))),
            Ok(r) => r,
        };

        let Some(ip_addr_str) = response.get(IPV4_ADDR_VAR) else {
            return Ok(None);
        };
        if ip_addr_str.trim().is_empty() {
            return Ok(None);
        }

        Ok(Some(ip_addr_str.parse()?))
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
            Some(v) if v.trim().is_empty() => return Ok(None),
            Some(v) => v,
        };
        let ipv6_addr = match response.get(IPV6_ADDR_VAR) {
            None => return Ok(None),
            Some(v) if v.trim().is_empty() => return Ok(None),
            Some(v) => v,
        };

        let valid_lifetime: u64 = valid_lifetime.parse()?;
        if valid_lifetime == 0 {
            Ok(None)
        } else {
            Ok(Some(ipv6_addr.parse()?))
        }
    }

    async fn get_current_ips(&self) -> Result<(Option<Ipv4Addr>, Option<Ipv6Addr>), ()> {
        let (ipv4, ipv6) = match self.get_current_external_ip().await {
            Ok(Some(IpAddr::V4(ip))) => (Some(ip), None),
            Ok(Some(IpAddr::V6(ip))) => (None, Some(ip)),
            Ok(None) => (None, None),
            Err(err) => {
                log::error!("{err:?}");
                return Err(());
            }
        };
        let ipv6 = if ipv6.is_some() {
            ipv6
        } else {
            match self.get_current_external_ipv6().await {
                Ok(ip) => ip,
                Err(err) => {
                    log::error!("{err:?}");
                    return Err(());
                }
            }
        };

        Ok((ipv4, ipv6))
    }
}

fn get_current_local_ips() -> Result<(Option<Ipv4Addr>, Option<Ipv6Addr>), ()> {
    let (ipv4, ipv6) = match local_ip_address::local_ip() {
        Ok(IpAddr::V4(ip)) => (Some(ip), None),
        Ok(IpAddr::V6(ip)) => (None, Some(ip)),
        Err(err) => {
            log::error!("{err:?}");
            (None, None)
        }
    };
    let ipv6 = if ipv6.is_some() {
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
    Ok((ipv4, ipv6))
}
