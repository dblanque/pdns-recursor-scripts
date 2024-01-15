-- Split DNS Filtering
-- Add your Default Web Reverse Proxy or desired Internal IP for your domain.

-- this function is hooked before resolving starts
function preresolve_lo(dq)
	-- check blocklist
	if local_domain_overrides:check(dq.qname) then
		if dq.qtype == pdns.A or dq.qtype == pdns.ANY then
			dq:addAnswer(pdns.A, options.private_zones_resolver_v4)
		end
		
		if dq.qtype == pdns.AAAA or dq.qtype == pdns.ANY then
			dq:addAnswer(pdns.AAAA, options.private_zones_resolver_v6)
		end
		
		return true
	end
	
	-- default, do not rewrite this response
	return false
end

-- Add preresolve function to table
if options.use_local_forwarder then
	-- List of private domains
	local_domain_overrides=newDS()
	loadDSFile(pdns_scripts_path.."/local-domains.list", local_domain_overrides)

	table.insert(preresolve_functions, preresolve_lo)
end