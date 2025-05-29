# DynDNS Update Daemon

A dynamic DNS (ddns) daemon that uses [Universal Plug and
Play](https://en.wikipedia.org/wiki/Universal_Plug_and_Play) (UPnP) to periodically check
the internet gateway's external IP address, and if it has changed push an update
to a ddns service or run a program.

If `router_ip` is set to the loopback address `127.0.0.1`, the ddns-update-daemon will
watch the local IP instead of the remote IP. In this case, no UPnP queries are sent.

Runs on Linux, Windows and Mac.  
(Uses [`rustls`](https://github.com/rustls/rustls) on Linux and the OS's default everywhere else).

**Features**
- Watching the external IP address with UPnP.
    - Note: UPnP port-forwarding doesn't need to be enabled for this.
- Watching the local IP address.
- Updaters
    - [Cloudflare](https://www.cloudflare.com/) by using the cloudflare API to update DNS records.
    - Requests to custom URLs (e.g. for dynu, no-ip, etc.).
    - Running a program.
- IPv6
    - Mostly only supported on [FRITZ!Box](https://avm.de/produkte/fritzbox/) routers.

## Installation

Install a prebuilt executable from the current [release](https://github.com/N3xed/ddns-update-daemon/releases).

Or, build from source and install with:
```
cargo install ddns-update-daemon
```
(Requires Rust to be installed).

## Configuration

ddns-update-daemon requires a configuration [`toml`](https://toml.io/en/) file as the first CLI argument.
(Run `ddns-update-daemon --help` to get help information about the CLI).

The configuration format is the following:
```toml
# The check interval in minutes; may be fractional (i.e. `0.5`). Required.
interval = 30
# The IP address of the internet gateway device the be queried. Optional.
# If not specified, the first discovered internet gateway device will be used.
# If set to loopback (127.0.0.1), the local IP address will be watched
# by querying the OS of the current local IP address.
# Can also be set to the UPnP InternetGatewayDevice endpoint URI (e.g.
# "http://192.168.1.1:49000/igd2desc.xml", it is printed in verbose mode with `-v`),
# in which case the network discovering step will be skipped.
router_ip = "192.168.1.1"

# Cloudflare DNS records to update. Optional.
[cloudflare]
# The cloudflare API access token.
api_token = "<token>"
# The cloudflare zone ID of the site to be updated.
zone_id = "<zone ID>"

# One or more records to be updated. Optional.
[[cloudflare.records]]
# The name of the DNS record. Required.
name = "@"
# The type of the DNS record. Required.
# Supportes "A" or "AAAA" records.
type = "A" # or "AAAA"

# Update a DynDNS service with a request to a URL. Optional.
[[urls]]
# The method used for the update request, supports "get", "post", "put", "patch", ...
# Optional, defaults to "get".
method = "get"

# The url to send the update request to, placeholders `{ipv4}` and `{ipv6}`
# will get replaced by the IPv4 and IPv6 address that was detected.
# Required.
url = "https://api.yourservice.com/nic/update?myip={ipv4}&myipv6={ipv6}"

# Additional headers to send, placeholders `{ipv4}` and `{ipv6}` will be replaced
# with the detected IPs in the header values.
# Optional.
headers = {"name" = "value", ...}

# The body of the request, if the request supports a body.
# Placeholders `{ipv4}` and `{ipv6}` will again be replaced by the detected IPs.
# Optional.
body = ""

# Run one or more programs when new IP(s) are detected. Optional.
[[runs]]
# The program to run and command line arguments,
# `{ipv4}` and `{ipv6}` will be replaced with the detected IPs in the arguments.
# Required.
cmd = ["myprog", "{ipv4}"]
```

License: MIT
