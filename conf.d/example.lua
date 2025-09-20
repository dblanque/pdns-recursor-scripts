-- /etc/powerdns/pdns-recursor-scripts/conf.d/example.lua
-- Beware, this file gets directly included into the hooks.lua file
-- You can load multiple config files, repeated options will be replaced by the last file.
-- Recommended names: overrides.lua || settings.lua || conf_dnsbl.lua || conf_local.lua
return {
	-- Local Domain Override Options
	main_domain = "example.com",
	use_one_to_one = false,
	one_to_one_subnets = {
		["127.0.0.0/16"]={
			["target"]="127.1.0.0/16",
			["acl"]={
				"100.64.0.0/10",
			}
		}
	},
	internal_reverse_proxy_v4 = "YOUR_INTERNAL_WEB_REVERSE_PROXY",
	internal_reverse_proxy_v6 = "YOUR_INTERNAL_WEB_REVERSE_PROXY",
	use_local_forwarder = false,
	exclude_main_domain_from_irp = true,
	exclude_local_forwarder_domains = {
		"external.example.com"
	},
	exclude_local_forwarder_domains_re = {
		"^(sub1|sub2).example.com$"
	},
	-- Exact matches have higher priority
	override_map = {
		{
			name="static.example.com",
			qtype="CNAME",
			content={
				"webserver.example.com"
			}
		}
	},
	--[[
		Regex matches are sequentially checked, so you should keep your higher
		specificity patterns on top.
	]]
	regex_map = {
		{
			pattern="^(mail|smtp|imap|smtps|smtp)\\..*$",
			qtype="CNAME",
			content={
				"mx.example.com"
			}
		},
		{
			pattern="^(a-record)\\..*$",
			qtype="A",
			content={
				"127.0.0.1"
			}
		},
		{
			pattern="^(cname-record-1)\\..*$",
			qtype="CNAME",
			content={
				"mail.example.com"
			}
		},
		{
			pattern="^.*$",
			qtype="NS",
			content={"ns1.example.com","ns2.example.com"}
		},
	},
	default_ttl = 900,
	-- For local cname chain resolution
	cname_resolver_enabled = false
	-- Usually you won't need to change the address.
	cname_resolver_address = "127.0.0.1"
	-- Change this if your PowerDNS Recursor is on a non-standard port.
	cname_resolver_port = 53

	-- Extra Debug Logging options
	debug_pre_override = false,
	debug_post_one_to_one = false,

	-- Malware Filter Options
	use_dnsbl = false, -- If you want to preresolve with DNSBL files (.list|.txt) in the dnsbl.d directory
	use_ipbl = false, -- If you want to postresolve with IPBL files (.list|.txt) in the ipbl.d directory
}