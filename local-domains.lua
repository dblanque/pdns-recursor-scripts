-- Split DNS Filtering
-- Add your Default Web Reverse Proxy or desired Internal IP for your domain.
if isModuleAvailable("rex_pcre") then
	re = require"rex_pcre"
elseif isModuleAvailable("rex_pcre2") then
	re = require"rex_pcre2"
else
	pdnslog("pdns-recursor-scripts local-domains.lua requires rex_pcre or rex_pcre2 to be installed", pdns.loglevels.Error)
	return false
end

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

local function preresolve_override(dq)
	-- check blocklist
	if not local_domain_overrides:check(dq.qname) then return false end
	local qname = qname_remove_trailing_dot(dq)
	local overridden = false
	if table_contains_key(g.options.override_map, qname) then
		for key, value in pairs(g.options.override_map) do
			if key ~= qname then goto continue end
			local dq_override = value
			local dq_type = dq_override[1]
			if dq.qtype ~= pdns[dq_type] then goto continue end
			local dq_values = dq_override[2]
			local dq_ttl = dq_override[3] or 300
			for i, v in ipairs(dq_values) do
				dq:addAnswer(pdns[dq_type], v, dq_ttl) -- Type, Value, TTL
			end
			if not overridden then overridden = true end
			::continue::
		end
	end
	return overridden
end

local function preresolve_regex(dq)
	-- check blocklist
	if not local_domain_overrides:check(dq.qname) then 
		pdnslog("loadDSFile(): Ignoring REGEX Pre-resolve for "..tostring(dq.qname), pdns.loglevels.Notice)
		return false
	end
	local qname = qname_remove_trailing_dot(dq)
	local overridden = false
	for key, value in pairs(g.options.regex_map) do
		if not re.match(qname, key) then goto continue end
		local dq_override = value
		local dq_type = dq_override[1]
		if dq.qtype ~= pdns[dq_type] then goto continue end
		local dq_values = dq_override[2]
		local dq_ttl = dq_override[3] or 300
		for i, v in ipairs(dq_values) do
			dq:addAnswer(pdns[dq_type], v, dq_ttl) -- Type, Value, TTL
		end
		if not overridden then overridden = true end
		::continue::
	end
	return overridden
end

local function preresolve_ns(dq)
	-- check blocklist
	if not local_domain_overrides:check(dq.qname) then return false end
	if not g.options.private_zones_ns_override then return false end

	if dq.qtype == pdns.NS then
		local qname = newDN(tostring(dq.qname))
		local modified = false
		for i, domain in ipairs(local_domain_overrides_t) do
			local parent_dn = newDN(domain)

			if qname:isPartOf(parent_dn) then
				local new_ns = {}
				local ns_override_auto
				local ns_override_map
				if g.options.private_zones_ns_override_prefixes
					and not g.options.private_zones_ns_override_map_only then
					ns_override_auto = table_len(g.options.private_zones_ns_override_prefixes) > 1
				end
				if g.options.private_zones_ns_override_map then
					if table_len(g.options.private_zones_ns_override_map) >= 1 then
						ns_override_map = table_contains_key(g.options.private_zones_ns_override_map, domain)
					end
				end
				if ns_override_map then
					for dom, s_list in pairs(g.options.private_zones_ns_override_map) do
						-- p == prefix, d == domain
						if dom == domain then
							for i, suffix in ipairs(s_list) do
								table.insert(new_ns, suffix)
							end
							break
						end
					end
				elseif ns_override_auto then
					new_ns = g.options.private_zones_ns_override_prefixes
				elseif not g.options.private_zones_ns_override_map_only then
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

-- Add preresolve functions to table, ORDER MATTERS
if g.options.use_local_forwarder then
	
	-- List of private domains
	local_domain_overrides=newDS()
	local_domain_overrides_t={}
	loadDSFile(g.pdns_scripts_path.."/local-domains.list", local_domain_overrides, local_domain_overrides_t)
	if g.options.override_map and table_len(g.options.override_map) >= 1 then
		addResolveFunction("pre", "preresolve_override", preresolve_override)
	end
	if g.options.regex_map and table_len(g.options.regex_map) >= 1 then
		addResolveFunction("pre", "preresolve_regex", preresolve_regex)
	end

	-- pdnslog("Loading preresolve_lo into pre-resolve functions.", pdns.loglevels.Notice)
	addResolveFunction("pre", "preresolve_lo", preresolve_lo)
	if g.options.private_zones_ns_override then
		addResolveFunction("pre", "preresolve_ns", preresolve_ns)
	end
else
	pdnslog("Local Domain Forwarder Override not enabled. Set overrides in file overrides.lua", pdns.loglevels.Notice)
end