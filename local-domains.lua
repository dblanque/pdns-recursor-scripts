-- Split DNS Filtering
-- Add your Default Web Reverse Proxy or desired Internal IP for your domain.

-- this function is hooked before resolving starts
function preresolve_lo(dq)
	-- check blocklist
	if local_domain_overrides:check(dq.qname) or filterips:check(dq.remoteaddr) or filtercidr:match(dq.remoteaddr) then
		if dq.qtype == pdns.A or dq.qtype == pdns.ANY then
			dq:addAnswer(pdns.A, "10.10.10.251")
		end
		
		if dq.qtype == pdns.AAAA or dq.qtype == pdns.ANY then
			dq:addAnswer(pdns.AAAA, "::1")
		end
		
		return true
	end
	
	-- default, do not rewrite this response
	return false
end

-- List of malware domains
local_domain_overrides=newDS()
loadFile("/etc/powerdns/local-domains.list", local_domain_overrides)