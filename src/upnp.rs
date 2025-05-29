use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use futures::pin_mut;
use futures::prelude::*;
use rupnp::http::Uri;
use rupnp::ssdp::URN;

const INTERNET_GATEWAY_DEVICE: [URN; 2] = [
    URN::device("schemas-upnp-org", "InternetGatewayDevice", 2),
    URN::device("schemas-upnp-org", "InternetGatewayDevice", 1),
];

const WAN_CONNECTION_DEVICE: [URN; 2] = [
    URN::device("schemas-upnp-org", "WANConnectionDevice", 2),
    URN::device("schemas-upnp-org", "WANConnectionDevice", 1),
];

const WANIP_CON_SERVICE: [URN; 2] = [
    URN::service("schemas-upnp-org", "WANIPConnection", 2),
    URN::service("schemas-upnp-org", "WANIPConnection", 1),
];

/// A service that queries the external IP address from the router using UPnP.
pub struct UPnPIpService {
    gateway: rupnp::Device,
    service_scpd: rupnp::scpd::SCPD,
    service: rupnp::Service,
}

impl UPnPIpService {
    /// Get the local IP address (host) of the gateway.
    pub fn router_ip(&self) -> &str {
        self.gateway.url().host().unwrap()
    }

    /// Get a friendly name of the gateway.
    pub fn router_name(&self) -> &str {
        self.gateway.friendly_name()
    }

    /// Get the URL to the gateway endpoint.
    pub fn gateway_endpoint(&self) -> &Uri {
        self.gateway.url()
    }

    /// Create a new service where `url` is the UPnP InternetGatewayDevice endpoint.
    pub async fn new_from_url(url: Uri) -> Result<Self> {
        let gateway = rupnp::Device::from_url(url.clone())
            .await
            .with_context(|| format!("url '{}' is not a valid UPnP device", url))?;

        if !INTERNET_GATEWAY_DEVICE
            .iter()
            .any(|d| gateway.device_type() == d)
        {
            bail!(
                "UPnP device '{}' at '{}' is not an InternetGatewayDevice v1 or v2",
                gateway.friendly_name(),
                gateway.url()
            );
        }
        Self::new_from_internet_gateway_device(gateway).await
    }

    /// Create a new service from the given UPnP gateway device.
    ///
    /// Get the `WANIPConnection` service from the given `InternetGatewayDevice`.
    pub async fn new_from_internet_gateway_device(gateway: rupnp::Device) -> Result<Self> {
        // Must be any of the InternetGatewayDevice versions we support.
        assert!(
            INTERNET_GATEWAY_DEVICE
                .iter()
                .any(|d| gateway.device_type() == d),
            "device not supported"
        );

        let wan_connection_device = gateway
            .devices_iter()
            .find(|d| {
                WAN_CONNECTION_DEVICE
                    .iter()
                    .any(|wan_device| d.device_type() == wan_device)
            })
            .with_context(|| anyhow!("could not find WAN connection device"))?;

        let service = wan_connection_device
            .services_iter()
            .find(|s| {
                WANIP_CON_SERVICE
                    .iter()
                    .any(|con_service| s.service_type() == con_service)
            })
            .with_context(|| anyhow!("could not find WAN IP connection service"))?;

        let service_scpd = service.scpd(gateway.url()).await?;

        Ok(UPnPIpService {
            service: service.clone(),
            service_scpd,
            gateway,
        })
    }

    /// Create a new service by discovering gateways where the IP address matches `ipaddr`.
    ///
    /// Get the `WANIPConnection` service from the `InternetGatewayDevice` matching `ipaddr` using
    /// [UPnP WAN Common Interface Config](http://upnp.org/specs/gw/UPnP-gw-WANCommonInterfaceConfig-v1-Service.pdf).
    pub async fn new_ip_connection_service(ipaddr: Option<std::net::IpAddr>) -> Result<Self> {
        let devices_v2 = rupnp::discover(
            &rupnp::ssdp::SearchTarget::URN(INTERNET_GATEWAY_DEVICE[0].clone()),
            Duration::from_secs(120),
            None,
        )
        .await?;
        let devices_v1 = rupnp::discover(
            &rupnp::ssdp::SearchTarget::URN(INTERNET_GATEWAY_DEVICE[1].clone()),
            Duration::from_secs(120),
            None,
        )
        .await?;

        let devices = futures::stream::select(devices_v2, devices_v1);
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
                            log::info!(
                                "Uri '{uri}' of discovered gateway '{device_name}' is not a valid IP address: {err:?}"
                            );
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

        Self::new_from_internet_gateway_device(gateway).await
    }

    /// Get the external ip address.
    async fn get_current_external_ip(&self) -> Result<Option<IpAddr>> {
        const ACTION: &str = "GetExternalIPAddress";
        const IPV4_ADDR_VAR: &str = "NewExternalIPAddress";

        let response = match self.service.action(self.gateway.url(), ACTION, "").await {
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
    async fn get_current_external_ipv6(&self) -> Result<Option<Ipv6Addr>> {
        const ACTION: &str = "X_AVM_DE_GetExternalIPv6Address";
        const IPV6_ADDR_VAR: &str = "NewExternalIPv6Address";
        const VALID_LIFETIME_VAR: &str = "NewValidLifetime";

        if !self
            .service_scpd
            .actions()
            .iter()
            .any(|act| act.name() == ACTION)
        {
            return Ok(None);
        }

        let response = match self.service.action(self.gateway.url(), ACTION, "").await {
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

    /// Query the current external IPv4 and IPv6 addresses of the gateway or [`None`] if
    /// unavailable.
    ///
    /// - IPv6 addresses are only supported on FRITZ!Box routers.
    ///
    /// The UPnP standard (i.e. the `WANIPConnection` service and `GetExternalIPAddress` action)
    /// only allow for IPv4 addresses, but IPv6 addresses are also parsed and returned for
    /// non-standard routers.
    ///
    /// FRITZ!Box routers implement a non-standard extension for `WANIPConnection` which allows to
    /// explicitly query the external IPv6 address with the `X_AVM_DE_GetExternalIPv6Address`
    /// action.
    pub async fn get_current_ips(&self) -> Result<(Option<Ipv4Addr>, Option<Ipv6Addr>)> {
        let (ipv4, ipv6) = match self.get_current_external_ip().await {
            Ok(Some(IpAddr::V4(ip))) => (Some(ip), None),
            Ok(Some(IpAddr::V6(ip))) => (None, Some(ip)),
            Ok(None) => (None, None),
            Err(err) => {
                return Err(err);
            }
        };
        let ipv6 = if ipv6.is_some() {
            ipv6
        } else {
            match self.get_current_external_ipv6().await {
                Ok(v) => v,
                Err(err) if ipv4.is_none() && ipv6.is_none() => return Err(err),
                Err(err) => {
                    // Do not return the error if we have obtained an IP already.
                    log::debug!("{:#}", err.context("UPnP request failed"));
                    None
                }
            }
        };

        Ok((ipv4, ipv6))
    }
}
