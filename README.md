# DynDNS Update Daemon

A dynamic DNS (ddns) daemon that uses [Universal Plug and
Play](https://en.wikipedia.org/wiki/Universal_Plug_and_Play) (UPnP) to periodically check
if the external IP address of the router changed, and if this is the case push an update
to a ddns service or run a program.

If `router_ip` is set to the loopback address `127.0.0.1`, the ddns-update-daemon will
watch the local IP instead of the remote IP. In this case, no UPnP queries are sent.

Runs on Linux, Windows and Mac.

**Supports**
- [Cloudflare](https://www.cloudflare.com/) by using the cloudflare API to update DNS records.
- Requests to custom URLs (e.g. for dynu, no-ip, etc.).
- Running a program.

## Configuration

ddns-update-daemon requires a `config.toml` file for its configuration.
It uses
1. the first command line argument as the `config.toml` file path,
2. the file at `<current directory>/config.toml` if it exists, or
3. the file at `<executable dir>/config.toml` if it exists.

The configuration format is the following:
```toml
# The check interval in minutes. Required.
interval = 30
# The IP address of the internet gateway device the be queried. Optional.
# If not specified, the first discovered internet gateway device will be used.
# If set to loopback (127.0.0.1), the local IP address will be watched
# by querying the OS of the current local IP address.
router_ip = "192.168.1.1"

# Cloudflare DNS records to update.
[cloudflare]
# The cloudflare API access token.
api_token = "<token>"
# The cloudflare zone ID of the site to be updated.
zone_id = "<zone ID>"

# One or more records to be updated.
[[cloudflare.records]]
# The name of the DNS record. Required.
name = "@"
# The type of the DNS record. Required.
# Supportes "A" or "AAAA" records.
type = "A" # or "AAAA"

# Update a DynDNS service with a request to a URL.
[[urls]]
# The method used for the update request, supports "get", "post", "put", "patch", ...
# Defaults to "get".
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

# Run one or more programs when new IP(s) are detected.
[[runs]]
# The program to run and command line arguments,
# `{ipv4}` and `{ipv6}` will be replaced with the detected IPs in the arguments.
cmd = ["myprog", "{ipv4}"]
```