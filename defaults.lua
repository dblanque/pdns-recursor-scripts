local options = {
	internal_reverse_proxy_v4="127.0.0.1",
	internal_reverse_proxy_v6="::1",
	use_dnsbl = false,
	use_ipbl = false,
	use_local_forwarder = false,
	private_zones_ns_override_prefixes = {}, -- Format: {"ns1","ns2","dns" (...) }

	private_zones_ns_override_map_only = false, -- Only apply NS Overrides if mapped
	private_zones_ns_override = false,

	-- Support multiple overrides
	private_zones_ns_override_map = {}, -- Format: { ["sub.example.com"]={"ns1","ns2"  (...) } }
	-- Support multiple overrides
	override_map = {}, -- Format: { ["sub.example.com"]= {TYPE:"A", {"value1","value2"  (...) }, TTL:300, REPLACE_ANY:false} }

	-- Escape dots with double backslash \\.
	regex_map = {}, -- Format: { ["*.example.com"]= {TYPE:"A", {"value1","value2"  (...) }, TTL:300, REPLACE_ANY:false} }
	default_ttl = 3600,
	dnsbl_whitelist = {}
}

return options