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

local function preresolve_ns(dq)
	-- check blocklist
	if not local_domain_overrides:check(dq.qname) then
		return false
	end
	if not g.options.private_zones_ns_override then return false end

	if dq.qtype == pdns.NS then
		local qname = newDN(tostring(dq.qname))
		local modified = false
		for i, domain in ipairs(local_domain_overrides_t) do
			local parent_dn = newDN(domain)

			if qname:isPartOf(parent_dn) then
				local new_ns
				local ns_override
				local ns_override_man
				if g.options.private_zones_ns_override_prefixes
					and not g.options.private_zones_ns_override_map_only then
					ns_override = table_len(g.options.private_zones_ns_override_prefixes) > 1
				end
				if g.options.private_zones_ns_override_map then
					if table_len(g.options.private_zones_ns_override_map) > 1 then
						ns_override_man = table_contains(g.options.private_zones_ns_override_map, domain, true)
					end
				end
				if ns_override_man then
					new_ns = {}
					for dom, s_list in pairs(g.options.private_zones_ns_override_map) do
						-- p == prefix, d == domain
						if dom == domain then
							for i, suffix in ipairs(s_list) do
								table.insert(new_ns, suffix)
							end
							break
						end
					end
				elseif ns_override then
					new_ns = g.options.private_zones_ns_override_prefixes
				else
					new_ns = {
						"ns1",
						"ns2",
						"dns"
					}
				end
				for i, ns in ipairs(new_ns) do
					dq:addAnswer(pdns.NS, ns .. "." .. domain, 300)
					if not modified then modified = true end
				end
				if modified == true then return modified end
			end
		end
	end
	return false
end

-- this function is hooked before resolving starts
local function preresolve_lo(dq)
	-- check blocklist
	if not local_domain_overrides:check(dq.qname) then
		return false
	end
	if dq.qtype == pdns.NS and g.options.private_zones_ns_override then
		return false
	end

	if dq.qtype == pdns.A or dq.qtype == pdns.ANY then
		dq:addAnswer(pdns.A, g.options.private_zones_resolver_v4)
	end

	if dq.qtype == pdns.AAAA or dq.qtype == pdns.ANY then
		dq:addAnswer(pdns.AAAA, g.options.private_zones_resolver_v6)
	end

	-- default, do not rewrite this response
	return true
end

-- Add preresolve function to table
if g.options.use_local_forwarder then
	-- List of private domains
	local_domain_overrides=newDS()
	local_domain_overrides_t={}
	loadDSFile(g.pdns_scripts_path.."/local-domains.list", local_domain_overrides, local_domain_overrides_t)

	-- pdnslog("Loading preresolve_lo into pre-resolve functions.", pdns.loglevels.Notice)
	addResolveFunction("pre", "preresolve_lo", preresolve_lo)
	if g.options.private_zones_ns_override then
		addResolveFunction("pre", "preresolve_ns", preresolve_ns)
	end
else
	pdnslog("Local Domain Forwarder Override not enabled. Set overrides in file overrides.lua", pdns.loglevels.Notice)
end