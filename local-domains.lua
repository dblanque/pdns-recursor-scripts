-- Split DNS Filtering
-- Add your Default Web Reverse Proxy or desired Internal IP for your domain.
if f.isModuleAvailable("rex_pcre") then
	re = require("rex_pcre")
elseif f.isModuleAvailable("rex_pcre2") then
	re = require("rex_pcre2")
else
	mainlog("pdns-recursor-scripts local-domains.lua requires rex_pcre or rex_pcre2 to be installed", pdns.loglevels.Error)
	return false
end
require("translate-ip")

-- List of private domains
local_domain_overrides=newDS()
local_domain_overrides_t={}

local function get_client(dq)
	if not dq then
		error("get_client requires a dq object.")
	end
	return dq.remoteaddr
end

local function is_internal_domain(dq, check_main)
	local main_domain_qname = newDN(
		tostring(g.options.main_domain or "example.com")
	)

	if not check_main then
		return local_domain_overrides:check(dq.qname)
	end

	return (
		local_domain_overrides:check(dq.qname) or
		dq.qname:isPartOf(main_domain_qname)
	)
end

-- loads contents of a file line by line into the given table
local function loadDSFile(filename, suffixMatchGroup, domainTable)
	if f.fileExists(filename) then
		for line in io.lines(filename) do
			suffixMatchGroup:add(line)
			table.insert(domainTable, line)
		end
		mainlog("loadDSFile(): " .. filename .. " successfully loaded", pdns.loglevels.Notice)
	else
		mainlog("loadDSFile(): could not open file " .. filename, pdns.loglevels.Warning)
	end
end

local function valid_type_replace(dq_type, replace_type)
	if dq_type ~= replace_type and
		(
			(dq_type == pdns.A and replace_type ~= pdns.CNAME) or
			(dq_type == pdns.AAAA and replace_type ~= pdns.CNAME)
		)
		then
		return false
	end
	return true
end

local function postresolve_one_to_one(dq)
	if not g.options.use_one_to_one or not g.options.one_to_one_subnets then
		return false
	end

	if not is_internal_domain(dq, true) then
		pdnslog(
			string.format(
				"postresolve_one_to_one(): Skipping One-to-One for external record %s",
				dq.qname:toString()
			),
			pdns.loglevels.Debug
		)
		return false
	else
		pdnslog(
			string.format(
				"postresolve_one_to_one(): Executing One-to-One for external record %s",
				dq.qname:toString()
			),
			pdns.loglevels.Debug
		)
	end

	local dq_records = dq:getRecords()
	local result_dq = {}
	local update_dq = false
	local client_addr = get_client(dq)

	for dr_index, dr in ipairs(dq_records) do
		local dr_content = dr:getContent()
		if not dr_content then
			pdnslog(
				"No DNSR Content for ".. tostring(dq.qname),
				pdns.loglevels.Debug
			)
			goto continue
		end
		-- Call function without raising exception to parent process
		local ok, dr_ca = pcall(newCA, dr_content)
		if not ok then
			table.insert(result_dq, dr)
			goto continue
		else
			local dr_ca_str = dr_ca:toString()
			pdnslog("DNSR Content: " .. dr_ca_str, pdns.loglevels.Debug)
	
			for _src, _opts in pairs(g.options.one_to_one_subnets) do
				local _tgt = _opts["target"]
				local _src_netmask = newNetmask(_src)
				local _src_prefix_len = _src:sub(-2)
				local _tgt_netmask = newNetmask(_tgt)
				local _tgt_prefix_len = _tgt:sub(-2)
				if not _src_prefix_len == _tgt_prefix_len then
					pdnslog(
						"One-to-One Source and Target must have same mask.",
						pdns.loglevels.Error
					)
				end

				pdnslog("One-to-One Source: " .. _src, pdns.loglevels.Debug)
				pdnslog("One-to-One Target: " .. _tgt, pdns.loglevels.Debug)
				local _acl = _opts["acl"]
				local _acl_masks = newNMG()
				_acl_masks:addMasks(_acl)
				pdnslog(
					"One-to-One will only apply to: " .. f.table_to_str(_acl, ", "),
					pdns.loglevels.Debug
				)
	
				-- If source subnet string matches
				if _src_netmask:match(dr_ca_str) then
					pdnslog(
						"Source Netmask Matched: " .. dr_ca_str,
						pdns.loglevels.Debug
					)
					-- If client ip is in One-to-One acl
					if _acl_masks:match(client_addr) then
						pdnslog(
							"Client Address Matched: " .. client_addr:toString(),
							pdns.loglevels.Debug
						)
						pdnslog(
							"Masked Net: " .. _src_netmask:getMaskedNetwork():truncate(_src_prefix_len):toString(),
							pdns.loglevels.Debug
						)
						local new_dr = dr_ca_str:gsub("^".._src, _tgt)
						update_dq = true
						dr:changeContent(new_dr)
					end
				end
			end
	
			table.insert(result_dq, dr)
		end
		::continue::
	end

	if not update_dq then
		return false
	else
		dq:setRecords(result_dq)
		pdnslog(
			string.format("Query Result %s", tostring(result_dq)),
			pdns.loglevels.Debug
		)
		return true
	end
end

local function preresolve_override(dq)
	-- do not pre-resolve if not in our domains

	if not is_internal_domain(dq, true) then
		pdnslog(
			string.format(
				"preresolve_override(): Skipping Override for external record %s",
				dq.qname:toString()
			),
			pdns.loglevels.Debug
		)
		return false
	else
		pdnslog(
			string.format(
				"preresolve_override(): Executing Override for external record %s",
				dq.qname:toString()
			),
			pdns.loglevels.Debug
		)
	end

	local qname = f.qname_remove_trailing_dot(dq)
	local overridden = false
	if f.table_contains_key(g.options.override_map, qname) then
		for key, value in pairs(g.options.override_map) do
			if key ~= qname then goto continue end
			local dq_override = value
			local dq_type = dq_override[1]
			local dq_replace_any = dq_override[4]
			if not valid_type_replace(dq.qtype, pdns[dq_type]) and not dq_replace_any then goto continue end
			local dq_values = dq_override[2]
			local dq_ttl = dq_override[3] or g.options.default_ttl
			for i, v in ipairs(dq_values) do
				dq:addAnswer(pdns[dq_type], v, dq_ttl) -- Type, Value, TTL
				-- If it's a CNAME Replacement, only allow one value.
				if pdns[dq_type] == pdns.CNAME then
					dq.followupFunction="followCNAMERecords"
					break
				end
			end
			if not overridden then overridden = true end
			::continue::
		end
	end

	local did_one_to_one = postresolve_one_to_one(dq)
	return overridden or did_one_to_one
end

local function preresolve_regex(dq)
	-- do not pre-resolve if not in our domains

	if not is_internal_domain(dq, true) then
		pdnslog(
			string.format(
				"preresolve_regex(): Skipping regex pre-resolve for external record %s",
				dq.qname:toString()
			),
			pdns.loglevels.Debug
		)
		return false
	else
		pdnslog(
			string.format(
				"preresolve_regex(): Executing regex pre-resolve for external record %s",
				dq.qname:toString()
			),
			pdns.loglevels.Debug
		)
	end

	local qname = f.qname_remove_trailing_dot(dq)
	local overridden = false
	for key, value in pairs(g.options.regex_map) do
		if not re.match(qname, key) then goto continue end
		local dq_override = value
		local dq_type = dq_override[1]
		local dq_replace_any = dq_override[4]
		if not valid_type_replace(dq.qtype, pdns[dq_type]) and not dq_replace_any then goto continue end
		local dq_values = dq_override[2]
		local dq_ttl = dq_override[3] or g.options.default_ttl
		for i, v in ipairs(dq_values) do
			dq:addAnswer(pdns[dq_type], v, dq_ttl) -- Type, Value, TTL
			-- If it's a CNAME Replacement, only allow one value.
			if pdns[dq_type] == pdns.CNAME then
				dq.followupFunction="followCNAMERecords"
				break
			end
		end
		
		pdnslog("preresolve_regex(): REGEX Overridden Result: "..tostring(overridden), pdns.loglevels.Debug)
		if not overridden then overridden = true end
		::continue::
	end

	local did_one_to_one = postresolve_one_to_one(dq)
	return overridden or did_one_to_one
end

local function preresolve_ns(dq)
	-- do not pre-resolve if not in our domains

	if not is_internal_domain(dq, true) then
		pdnslog(
			string.format(
				"preresolve_ns(): Skipping NS pre-resolve for external record %s",
				dq.qname:toString()
			),
			pdns.loglevels.Debug
		)
		return false
	else
		pdnslog(
			string.format(
				"preresolve_ns(): Executing NS pre-resolve for external record %s",
				dq.qname:toString()
			),
			pdns.loglevels.Debug
		)
	end

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
					ns_override_auto = f.table_len(g.options.private_zones_ns_override_prefixes) > 1
				end
				if g.options.private_zones_ns_override_map then
					if f.table_len(g.options.private_zones_ns_override_map) >= 1 then
						ns_override_map = f.table_contains_key(g.options.private_zones_ns_override_map, domain)
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
local function preresolve_rpr(dq)
	-- do not pre-resolve if not in our domains

	if not is_internal_domain(dq, true) then
		pdnslog(
			string.format(
				"preresolve_rpr(): Skipping reverse proxy replacement pre-resolve for external record %s",
				dq.qname:toString()
			),
			pdns.loglevels.Debug
		)
		return false
	else
		pdnslog(
			string.format(
				"preresolve_rpr(): Executing reverse proxy replacement pre-resolve for external record %s",
				dq.qname:toString()
			),
			pdns.loglevels.Debug
		)
	end

	local set_internal_reverse_proxy = false
	if dq.qtype == pdns.A or dq.qtype == pdns.ANY then
		if g.options.internal_reverse_proxy_v4 then
			set_internal_reverse_proxy = true
			dq:addAnswer(
				pdns.A,
				g.options.internal_reverse_proxy_v4,
				g.options.default_ttl
			)
		end
	end

	if dq.qtype == pdns.AAAA or dq.qtype == pdns.ANY then
		if g.options.internal_reverse_proxy_v6 then
			set_internal_reverse_proxy = true
			dq:addAnswer(
				pdns.AAAA,
				g.options.internal_reverse_proxy_v6,
				g.options.default_ttl
			)
		end
	end

	local did_one_to_one = postresolve_one_to_one(dq)
	return set_internal_reverse_proxy or did_one_to_one
end

-- Add preresolve functions to table, ORDER MATTERS
if g.options.use_local_forwarder then
	loadDSFile(g.pdns_scripts_path.."/local-domains.list", local_domain_overrides, local_domain_overrides_t)
	if g.options.override_map and f.table_len(g.options.override_map) >= 1 then
		mainlog("Loading preresolve_override into pre-resolve functions.", pdns.loglevels.Notice)
		f.addHookFunction("pre", "preresolve_override", preresolve_override)
	end

	if g.options.regex_map and f.table_len(g.options.regex_map) >= 1 then
		mainlog("Loading preresolve_regex into pre-resolve functions.", pdns.loglevels.Notice)
		f.addHookFunction("pre", "preresolve_regex", preresolve_regex)
	end

	if g.options.private_zones_ns_override then
		mainlog("Loading preresolve_ns into pre-resolve functions.", pdns.loglevels.Notice)
		f.addHookFunction("pre", "preresolve_ns", preresolve_ns)
	end

	if g.options.use_one_to_one then
		mainlog("Loading postresolve_one_to_one into post-resolve functions.", pdns.loglevels.Notice)
		f.addHookFunction("post", "postresolve_one_to_one", postresolve_one_to_one)
	end

	mainlog("Loading preresolve_rpr into pre-resolve functions.", pdns.loglevels.Notice)
	f.addHookFunction("pre", "preresolve_rpr", preresolve_rpr)
else
	mainlog("Local Domain Forwarder Override not enabled. Set overrides in file overrides.lua", pdns.loglevels.Notice)
end
