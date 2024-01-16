local options = {
	private_zones_resolver_v4="127.0.0.1",
	private_zones_resolver_v6="::1",
	use_dnsbl = false,
	use_ipbl = false,
	use_local_forwarder = false,
	private_zones_ns_override_prefixes = {}, -- Format: prefix value only (ns1)
	private_zones_ns_override_map = {}, -- Format: key: prefix (ns1), value: domain (example.com) => ns1.example.com
	private_zones_ns_override = false
}

return options