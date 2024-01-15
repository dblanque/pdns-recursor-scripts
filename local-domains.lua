-- Split DNS Filtering
-- Add your Default Web Reverse Proxy or desired Internal IP for your domain.

-- loads contents of a file line by line into the given table
local function loadDSFile(filename, list)
	if fileExists(filename) then
		for line in io.lines(filename) do
			list:add(line)
		end
		pdnslog("loadDSFile(): " .. filename .. " successfully loaded", pdns.loglevels.Notice)
	else
		pdnslog("loadDSFile(): could not open file " .. filename, pdns.loglevels.Warning)
	end
end

-- this function is hooked before resolving starts
function preresolve_lo(dq)
	-- check blocklist
	if local_domain_overrides:check(dq.qname) then
		if dq.qtype == pdns.A or dq.qtype == pdns.ANY then
			dq:addAnswer(pdns.A, g.options.private_zones_resolver_v4)
		end
		
		if dq.qtype == pdns.AAAA or dq.qtype == pdns.ANY then
			dq:addAnswer(pdns.AAAA, g.options.private_zones_resolver_v6)
		end
		
		return true
	end
	
	-- default, do not rewrite this response
	return false
end

-- Add preresolve function to table
if g.options.use_local_forwarder then
	-- List of private domains
	local_domain_overrides=newDS()
	loadDSFile(g.pdns_scripts_path.."/local-domains.list", local_domain_overrides)

	pdnslog("Loading preresolve_lo into pre-resolve functions.", pdns.loglevels.Notice)
	addResolveFunction("pre", "preresolve_lo", preresolve_lo)
else
	pdnslog("Local Domain Forwarder not enabled. Set overrides in file overrides.lua", pdns.loglevels.Notice)
end