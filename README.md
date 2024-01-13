# Scripts for PowerDNS Split-DNS and Malware Filtering

To use, clone this repository onto your `/etc/powerdns` directory and add
or modify the following line in your PowerDNS Recursor Configuration File:

```conf
# /etc/powerdns/recursor.conf
lua-dns-script=/etc/powerdns/hooks.lua
```

You must parse your IP Block-lists into the file `/etc/powerdns/filter-domains.list`

# IPBL Examples

## Emerging Threats
* Blocked IPs: <https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt>
* Compromised IPs: <https://rules.emergingthreats.net/blockrules/compromised-ips.txt>