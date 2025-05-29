use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use upnp::UPnPIpService;

mod cloudflare;
mod upnp;
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
    use std::{path::Path, str::FromStr};

    use crate::{cloudflare, url};

    #[derive(Debug, Clone)]
    pub struct Uri(pub rupnp::http::Uri);
    impl<'de> serde::Deserialize<'de> for Uri {
        fn deserialize<D>(d: D) -> std::result::Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            use serde::Deserialize;

            let uri: String = Deserialize::deserialize(d)?;
            match rupnp::http::Uri::from_str(&uri) {
                Ok(uri) => Ok(Uri(uri)),
                Err(err) => Err(serde::de::Error::custom(format!("{}", err))),
            }
        }
    }

    #[derive(Debug, serde::Deserialize, Clone)]
    #[serde(untagged, expecting = "an IP address or a UPnP InternetGatewayDevice endpoint URI")]
    pub enum Router {
        Ip(std::net::IpAddr),
        Uri(Uri),
    }

    #[derive(Debug, serde::Deserialize)]
    pub struct Config {
        /// Optional router IP address that will be used to query the external IP address using UPnP.
        /// May also be a URI to the UPnP InternetGatewayDevice endpoint.
        pub router_ip: Option<Router>,
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

            match &self.router_ip {
                None => {
                    log::info!("No router_ip configured, descovering from the network.")
                }
                Some(Router::Ip(ip)) if ip.is_loopback() => {
                    log::info!("Found loopback as router_ip, watching local IP address instead.")
                }
                Some(Router::Ip(ip)) => {
                    log::info!("Using configured router_ip '{ip}'.")
                }
                Some(Router::Uri(Uri(uri))) => {
                    log::info!("Using configured router_ip `{uri}` as UPnP InternetGatewayDevice endpoint.");
                }
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
pub async fn main() -> anyhow::Result<()> {
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
    let mut service = IpService::new(router_ip.clone(), true).await?;

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
        "interval * 60 ({interval}) must be positive and less than `2^64`"
    );
    log::info!("Using {interval} seconds interval.");

    let interval = tokio::time::Duration::from_secs(interval as u64);
    let mut curr_ipv4: Option<Ipv4Addr> = None;
    let mut curr_ipv6: Option<Ipv6Addr> = None;
    loop {
        let (next_ipv4, next_ipv6) = match service.get_current_ips().await {
            Some(v) => v,
            None if service.is_upnp() => {
                log::info!("Rediscovering internet gateway..");
                // Try to recreate the IpService, since the previous call errored.
                match IpService::new(router_ip.clone(), false).await {
                    Ok(new_service) => service = new_service,
                    Err(err) => log::error!("{err:#}"),
                }
                (None, None)
            }
            None => (None, None),
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

fn replace_placehoders(s: &str, ipv4: &str, ipv6: &str) -> String {
    let s = s.replace("{ipv4}", ipv4);
    s.replace("{ipv6}", ipv6)
}

pub enum IpService {
    UPnP(UPnPIpService),
    Local,
}

impl IpService {
    pub fn is_upnp(&self) -> bool {
        matches!(self, Self::UPnP(_))
    }

    pub async fn get_current_ips(&self) -> Option<(Option<Ipv4Addr>, Option<Ipv6Addr>)> {
        match self {
            IpService::UPnP(s) => s
                .get_current_ips()
                .await
                .map_err(|err| log::error!("{:#}", err.context("UPnP request failed")))
                .ok(),
            IpService::Local => get_current_local_ips(),
        }
    }

    /// Create an IP address service.
    /// Query local IP address if `ipaddr` is loopback otherwise use UPnP to
    /// query the router's given by `ipaddr` or the first discovered.
    pub async fn new(ipaddr: Option<config::Router>, verbose: bool) -> Result<Self> {
        async fn discover(addr: Option<IpAddr>, verbose: bool) -> Result<UPnPIpService> {
            if verbose {
                log::info!("Discovering internet gateway..");
            }
            UPnPIpService::new_ip_connection_service(addr).await
        }

        let upnp_service = match ipaddr {
            Some(config::Router::Ip(ip)) if ip.is_loopback() => {
                if verbose {
                    log::info!("Watching the local IP address.");
                }
                return Ok(IpService::Local);
            }
            None => discover(None, verbose).await?,
            Some(config::Router::Ip(ip)) => discover(Some(ip), verbose).await?,
            Some(config::Router::Uri(config::Uri(uri))) => {
                log::debug!("Using InternetGatewayDevice URI '{}'.", uri);
                UPnPIpService::new_from_url(uri).await?
            }
        };

        log::info!(
            "Using router '{}' at '{}' to get the external IP address.",
            upnp_service.router_name(),
            upnp_service.router_ip()
        );
        Ok(IpService::UPnP(upnp_service))
    }
}

pub fn get_current_local_ips() -> Option<(Option<Ipv4Addr>, Option<Ipv6Addr>)> {
    let (ipv4, ipv6) = match local_ip_address::local_ip() {
        Ok(IpAddr::V4(ip)) => (Some(ip), None),
        Ok(IpAddr::V6(ip)) => (None, Some(ip)),
        Err(err) => {
            log::error!(
                "{:#}",
                anyhow!(err).context("failed to query the system IP address")
            );
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
    Some((ipv4, ipv6))
}
