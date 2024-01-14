# Scripts for PowerDNS Split-DNS and Malware Filtering

Script Repository maintained by Dylan Blanqué. Created in 2024.

# REQUIREMENTS

You must have `lua-rex-pcre` or `lua-rex-pcre2` installed (Can be done with `apt` or `luarocks`).

# INSTRUCTIONS

To use, clone this repository onto your `/etc/powerdns` directory and add
or modify the following line in your PowerDNS Recursor Configuration File:

```conf
# /etc/powerdns/recursor.conf
lua-dns-script=/etc/powerdns/pdns-recursor-scripts/hooks.lua
```

# SUPPORTED

## IPBL Examples

### Emerging Threats
* Blocked IPs: <https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt>
* Compromised IPs: <https://rules.emergingthreats.net/blockrules/compromised-ips.txt>

## DNSBL Examples

* Hagezi DNS Blocklists: <https://github.com/hagezi/dns-blocklists>

## Supported Syntaxes
* Adblock
* Plain List
* PCRE Regex
* Wildcard

# Documentation Used

The following PowerDNS Documents were used as reference.

<https://docs.powerdns.com/authoritative/genindex.html>
<https://docs.powerdns.com/recursor/lua-scripting/configure.html>
<https://docs.powerdns.com/recursor/lua-scripting/index.html>
<https://docs.powerdns.com/recursor/lua-scripting/dq.html#dnsrecord-object>
<https://docs.powerdns.com/recursor/lua-scripting/netmask.html>