-- Split DNS Filtering
-- Add your Default Web Reverse Proxy or desired Internal IP for your domain.

-- loads contents of a file line by line into the given table
local function loadDSFile(filename, suffixMatchGroup, domainTable)
	if fileExists(filename) then
		for line in io.lines(filename) do
			suffixMatchGroup:add(line)
			table.insert(domainTable, line)
		end
		pdnslog("loadDSFile(): " .. filename .. " successfully loaded", pdns.loglevels.Notice)
	else
		pdnslog("loadDSFile(): could not open file " .. filename, pdns.loglevels.Warning)
	end
end

-- this function is hooked before resolving starts
function preresolve_lo(dq)
	-- check blocklist
		if dq.qtype == pdns.NS and g.options.private_zones_ns_override then
			local qname = newDN(dq.qname)
			local parent
			for i, domain in ipairs(local_domain_overrides_t) do
				if name:isPartOf(domain) then
					parent = domain
				end
			end
			if ns_check then
				local new_ns = {
					"ns1."..parent,
					"ns2."..parent,
					"dns."..parent
				}
				for i, ns in ipairs(new_ns) do
					dq:addAnswer(pdns.NS, ns)
				end
				return true
			end
		end

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
	local_domain_overrides_t={}
	loadDSFile(g.pdns_scripts_path.."/local-domains.list", local_domain_overrides, local_domain_overrides_t)

	pdnslog("Loading preresolve_lo into pre-resolve functions.", pdns.loglevels.Notice)
	addResolveFunction("pre", "preresolve_lo", preresolve_lo)
else
	pdnslog("Local Domain Forwarder Override not enabled. Set overrides in file overrides.lua", pdns.loglevels.Notice)
end