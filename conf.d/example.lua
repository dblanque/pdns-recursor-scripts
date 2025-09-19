-- Beware, this file gets directly included into the hooks.lua file
-- You can load multiple config files, repeated options will be replaced by the last file.
-- Recommended names: overrides.lua || settings.lua || conf_dnsbl.lua || conf_local.lua
return {
	-- Local Domain Override Options
	main_domain = "example.com",
	use_one_to_one = false,
    one_to_one_subnets = {
        ["127.0.0.0/16"]={
			["target"]="100.65.1.0/16",
			["acl"]={
				"100.64.0.0/16",
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
	override_map = {
		["something.example.com"]={
			qtype="A",
			content={"127.0.0.1", "127.0.0.2"}
		}
	},
	regex_map = {
		["^(mail|smtp|imap|smtps|smtp)\\..*$"]={
			qtype="CNAME",
			content={"mailserver.example.com"},
		},
		["^(dns|dot|doh|ns[0-9])\\..*$"]={
			qtype="A",
			content={"127.0.0.1"},
		}
	},
	default_ttl = 900,

	-- Malware Filter Options
	use_dnsbl = false, -- If you want to preresolve with DNSBL files (.list|.txt) in the dnsbl.d directory
	use_ipbl = false, -- If you want to postresolve with IPBL files (.list|.txt) in the ipbl.d directory
}