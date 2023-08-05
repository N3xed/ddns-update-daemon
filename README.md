# Dyn DNS Update Daemon

A dynamic DNS (ddns) daemon that uses [Universal Plug and
Play](https://en.wikipedia.org/wiki/Universal_Plug_and_Play) (UPnP) to periodically check
if the external IP address of the router changed, and if this is the case push an update
to a ddns service.

**Note**  
Currently only [cloudflare](https://www.cloudflare.com/) is supported.

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
name = "n3xed.ch"
# The type of the DNS record. Required.
# Supportes "A" or "AAAA" records.
type = "A" # or "AAAA"
```