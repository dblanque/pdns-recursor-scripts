# Scripts for PowerDNS Split-DNS and Malware Filtering

## Update 1.01
* Whitelisting for DNSBL Domains has been moved to a separate file instead of the
Lua config (See corresponding section below).
* Fixes to syntax detection
* Improvements to use Native PowerDNS DS object in all syntax modes except PCRE.
* Improvements to comment detection regexes.

This script-set was created to facilitate Malware Filtering and Split-DNS support on
PowerDNS Recursor Services.

You may include DNSBLs and IPBLs with different formats such as Adblock, REGEX, Wildcard or
Plain Domain Lists (hosts format is excluded as that is supported by default
by PowerDNS Recursor).

It's especially useful in cases where you might have a Reverse Proxy as a sort of *Gateway*
that handles all your web services, or cases where you might need to replace Internal DNS
Zone Records through REGEX Patterns.

Script Repository maintained by Dylan Blanqué. Created January 2024.

### Would you like to support me?
<a href='https://ko-fi.com/E1E2YQ4TG' target='_blank'>
	<img
		height='36'
		style='border:0px;height:36px;'
		src='https://storage.ko-fi.com/cdn/kofi2.png?v=3'
		border='0'
		alt='Buy Me a Coffee at ko-fi.com' />
</a>

# REQUIREMENTS

You must have `lua-rex-pcre` or `lua-rex-pcre2` installed (Can be done with
`apt` or `luarocks`).

E.g.:
```bash
apt update -y
apt install lua-rex-pcre -y || apt install lua-rex-pcre2 -y
```

# INSTRUCTIONS

To use this script-set, after you've ensured the requirements are met you can
clone this repository with `git` onto your `/etc/powerdns` directory and add
or modify the following line in your PowerDNS Recursor Configuration File:

```bash
cd /etc/powerdns
git clone https://github.com/dblanque/pdns-recursor-scripts
```

```conf
# /etc/powerdns/recursor.conf (Legacy)
lua-dns-script=/etc/powerdns/pdns-recursor-scripts/hooks.lua
```

```yaml
# /etc/powerdns/recursor.conf (YAML)
recursor:
  lua_dns_script: /etc/powerdns/pdns-recursor-scripts/hooks.lua
```

## Local Domain Overriding (For Split-DNS)

For Split DNS (and to reduce the usage of NAT Reflection) you may use the
following options in the following files:
* `/etc/powerdns/pdns-recursor-scripts/conf.d/settings.lua`
* `/etc/powerdns/pdns-recursor-scripts/conf.d/local-resolve.lua`

Bear in mind you must also configure your internal domains in the `local-domains.list`
file for this feature to work properly `(See local-domains-example.list)`.

You can override NS Servers for your local zones, as well as standard record types
such as CNAME, A, and AAAA, for example.

```lua
-- /etc/powerdns/pdns-recursor-scripts/conf.d/local-resolve.lua
return {
        internal_reverse_proxy_v4 = "YOUR_INTERNAL_WEB_REVERSE_PROXY",
        internal_reverse_proxy_v6 = "YOUR_INTERNAL_WEB_REVERSE_PROXY",
        use_local_forwarder = true,
        private_zones_ns_override_map_only = true,
        private_zones_ns_override_map = {
                ['domain.com'] = {'ns1','ns2','dns','dot','doh'}
        },
        private_zones_ns_override = true,
        override_map = {
                ['something.domain.com']={
                        "A",
                        {"127.0.0.1", "127.0.0.2"}
                }
        },
        regex_map = {
                ['^(mail|smtp|imap|smtps|smtp)\\..*$']={
                        "CNAME",
                        {"mailserver.domain.com"}
                },
                ['^(dns|dot|doh|ns[0-9])\\..*$']={
                        "A",
                        {"127.0.0.1"}
                }
        },
        default_ttl = 900
}
```

## Blocklist Filtering

For Blocklists and some Malware Filtering DNS you may use the following
options in the `/etc/powerdns/pdns-recursor-scripts/conf.d/malware-filter.lua`.

### Supported Syntaxes
* Adblock: ||example.com^
* PCRE: Assumed if matches special regex chars and not Adblock Syntax
* HOSTS: Entries starting with the following IPs will be ingested/blocked
  * 0.0.0.0
  * 127.0.0.1
  * ::
  * 2001:1::1
* Standard: A normal TXT Domain list.

### Whitelist

To whitelist domains create a `/etc/powerdns/pdns-recursor-scripts/conf.d/dnsbl_whitelist.txt`
file with one domain per line.

```lua
-- /etc/powerdns/pdns-recursor-scripts/conf.d/malware-filter.lua
return {
	use_dnsbl = true, -- If you want to preresolve with DNSBL files (.list|.txt|.hosts) in the dnsbl.d directory
	use_ipbl = true, -- If you want to postresolve with IPBL files (.list|.txt|.hosts) in the ipbl.d directory
}
```

# RE-LOADING DNSBL/IPBL

To reload the lists all you need to do is execute the following command:

`rec_control reload-lua-script`
OR
`rec_control reload-lua-script /etc/powerdns/pdns-recursor-scripts/hooks.lua`

You may also add this onto a cronjob with the following format to reload every day at 00:00.

```cron
00 00   * * *   root    rec_control reload-lua-script /etc/powerdns/pdns-recursor-scripts/hooks.lua 2&>1 /dev/null
```

# SUPPORTED

## IPBLs used for Testing

### Emerging Threats
* Blocked IPs: <https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt>
* Compromised IPs: <https://rules.emergingthreats.net/blockrules/compromised-ips.txt>

## DNSBLs used for Testing

* Hagezi DNS Blocklists: <https://github.com/hagezi/dns-blocklists>
* Steven Black Hosts: 

# Documentation Used

The following PowerDNS Documents were used as reference.

* <https://docs.powerdns.com/authoritative/genindex.html>
* <https://docs.powerdns.com/recursor/lua-scripting/configure.html>
* <https://docs.powerdns.com/recursor/lua-scripting/index.html>
* <https://docs.powerdns.com/recursor/lua-scripting/dq.html#dnsrecord-object>
* <https://docs.powerdns.com/recursor/lua-scripting/netmask.html>

# CONTRIBUTING

Feel free to contribute to the project with fixes or feature ideas you might need!

# PROJECT LICENSE

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://fsf.org/>.

This program comes with ABSOLUTELY NO WARRANTY.
