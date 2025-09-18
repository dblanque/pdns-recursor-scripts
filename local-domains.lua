-- Split DNS Filtering
-- Add your Default Web Reverse Proxy or desired Internal IP for your domain.
if f.isModuleAvailable("rex_pcre") then
	re = require "rex_pcre"
elseif f.isModuleAvailable("rex_pcre2") then
	re = require "rex_pcre2"
else
	mainlog("pdns-recursor-scripts local-domains.lua requires rex_pcre or rex_pcre2 to be installed", pdns.loglevels.Error)
	return false
end
require "ip-translate"

-- List of private domains
local local_domain_overrides = newDS()
local local_domain_overrides_t = {}
local local_whitelist_ds = newDS()
local conf_domain_overrides = newDS()

-- Populate whitelist
if g.options.exclude_local_forwarder_domains then
	for _, domain in ipairs(g.options.exclude_local_forwarder_domains) do
		local_whitelist_ds:add(newDN(domain))
	end
end

-- Populate Local Conf. Overrides
if g.options.override_map then
	for _, domain in ipairs(g.options.override_map) do
		conf_domain_overrides:add(newDN(domain))
	end
end

local function is_internal_domain(dq, check_main)
	local main_domain_qname = newDN(
		tostring(g.options.main_domain or "example.com")
	)

	if not check_main then
		return local_domain_overrides:check(dq.qname)
	end
	local r = (
		local_domain_overrides:check(dq.qname) or
		dq.qname:isPartOf(main_domain_qname)
	)
	pdnslog(
		string.format(
			"Checked if %s is internal (%s).",
			dq.qname:toString(),
			tostring(r)
		)
	)
	return r
end

local function has_a_or_aaaa(dq)
	local dq_records = dq:getRecords()
	if not dq_records then
		return false
	end

	for _idx, record in ipairs(dq_records) do
		if record.type == pdns.A or record.type == pdns.AAAA then
			return true
		end
	end
	return false
end

local function is_excluded_from_local(dq)
	local excl_exact = g.options.exclude_local_forwarder_domains
	local excl_patterns = g.options.exclude_local_forwarder_domains_re
	if not excl_exact and not excl_patterns then
		return false
	end
	if excl_patterns then
		for i, pattern in ipairs(excl_patterns) do
			if re.match(dq.qname:toString(), pattern) then
				return true
			end
		end
	end
	return local_whitelist_ds:check(dq.qname)
end

local function has_conf_override(dq)
	-- check override_map
	-- check regex_map
	local excl_exact = g.options.override_map
	local excl_patterns = g.options.regex_map
	if not excl_exact and not excl_patterns then
		return false
	end
	if excl_patterns then
		for pattern, replace_data in pairs(excl_patterns) do
			if (
				re.match(dq.qname:toString(), pattern) and
				pdns[replace_data.qtype] == dq.qtype
			) then
				return true
			end
			::continue::
		end
	end
	return conf_domain_overrides:check(dq.qname)
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
	local types_match = dq_type == replace_type
	local valid_type_replaces = (
		-- A is not replaced with CNAME
		(dq_type == pdns.A and replace_type == pdns.CNAME) or
		-- AAAA is not replaced with CNAME
		(dq_type == pdns.AAAA and replace_type == pdns.CNAME)
	)
	return types_match or valid_type_replaces
end

local function postresolve_one_to_one(dq)
	local function fn_debug(msg)
		if not g.options.debug_post_one_to_one then
			return false
		end
		pdnslog(msg, pdns.loglevels.Debug)
	end

	if not g.options.use_one_to_one or not g.options.one_to_one_subnets then
		return false
	end

	if is_excluded_from_local(dq) then
		return false
	end

	if not has_a_or_aaaa(dq) then
		pdnslog(
			string.format(
				"postresolve_one_to_one(): No 1-to-1 required for record %s",
				dq.qname:toString()
			),
			pdns.loglevels.Debug
		)
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
	local client_addr = dq.remoteaddr
	local prev_cname = nil

	for _, record in ipairs(dq_records) do
		local record_content = record:getContent()
		f.dr_log_content(record_content)
		if not record_content then
			goto continue
		end

		-- Call function without raising exception to parent process
		-- CA = ComboAddress Object
		local ok, record_ca = pcall(newCA, record_content)
		if not ok then
			--[[
				If it's a CNAME then the last CNAME of the Chain should be
				used for all A/AAAA Records, and the complete chain should be
				shown in the response.
			]]
			if record.type == pdns.CNAME then
				prev_cname = record_content
				fn_debug("Set previous CNAME: " .. prev_cname)
			end
			table.insert(result_dq, record)
			goto continue
		else
			-- Convert ComboAddress to str
			local record_addr = record_ca:toString()
			fn_debug("DNSR ComboAddress: " .. record_addr)

			-- Check if record is within 1-to-1 requested subnets
			for _src, _opts in pairs(g.options.one_to_one_subnets) do
				local _tgt = _opts["target"]
				-- Make source netmask
				local _src_netmask = newNetmask(_src)
				local _src_prefix_len = tonumber(_src:sub(-2))
				-- Make target netmask
				local _tgt_netmask = newNetmask(_tgt)
				local _tgt_prefix_len = tonumber(_tgt:sub(-2))
				-- Compare Prefix length for both netmasks
				if _src_prefix_len ~= _tgt_prefix_len then
					fn_debug(
						"One-to-One Source and Target must have same mask."
					)
					goto continue
				end

				fn_debug("One-to-One Source: " .. _src)
				fn_debug("One-to-One Target: " .. _tgt)
				-- Parse ACLs for 1-to-1
				local _acl = _opts["acl"]
				local _acl_masks = newNMG()
				_acl_masks:addMasks(_acl)
				fn_debug(
					"One-to-One will only apply to: " ..
					f.table_to_str(_acl, ", ")
				)
	
				-- If source subnet matches
				if _src_netmask:match(record_addr) and _acl_masks:match(client_addr) then
					fn_debug("Source Netmask Matched: " .. record_addr)
					fn_debug("ACL Netmask Matched: " .. client_addr:toString())
					-- If client ip is in 1-to-1 ACLs...
					local new_addr = translate_ip(
						record_addr,
						_src,
						_tgt
					)
					update_dq = true
					if prev_cname then
						record.name = newDN(prev_cname)
					end
					record:changeContent(new_addr)
				end
			end
	
			table.insert(result_dq, record)
		end
		::continue::
	end

	if update_dq then
		dq:setRecords(result_dq)
		pdnslog(
			string.format(
				"postresolve_one_to_one(): Result %s",
				f.table_to_str(
					result_dq,
					", ",
					function (dr) return dr:getContent() end
				)
			),
			pdns.loglevels.Debug
		)
	end

	fn_debug("Did not perform one-to-one.")
	return true
end

function cname_override_patch(dq)
	--[[
		Function to patch CNAME on NS Record Replacements.
	]]
	local dq_records = dq:getRecords()
	local cname_index = nil
	local has_cname = false
	local has_ns = false
	if not dq_records then
		return false
	end

	for _idx, record in ipairs(dq_records) do
		-- This will only take the last CNAME in the chain
		if record.type == pdns.CNAME then
			has_cname = true
			cname_index = _idx
		elseif record.type == pdns.NS then
			has_ns = true
		end
	end

	pdnslog(
		"cname_override_patch(): has_cname = ".. tostring(has_cname),
		pdns.loglevels.Debug
	)
	pdnslog(
		"cname_override_patch(): has_ns = ".. tostring(has_ns),
		pdns.loglevels.Debug
	)
	if has_cname and has_ns then
		dq:setRecords({dq_records[cname_index]})
		return true
	end
	return false
end

local function replace_content(dq, dq_override)
	local dq_type = dq_override["qtype"]
	local dq_replace_any = dq_override["replace_any"]
	if (
		not valid_type_replace(dq.qtype, pdns[dq_type]) and
		not dq_replace_any
	) then
		return false
	end

	local dq_values = dq_override["content"]
	local dq_ttl = dq_override["ttl"] or g.options.default_ttl
	for i, v in ipairs(dq_values) do
		-- Add answer
		dq:addAnswer(pdns[dq_type], v, dq_ttl) -- Type, Value, TTL
		-- If it's a CNAME Replacement, only allow one value.
		if pdns[dq_type] == pdns.CNAME then
			-- Don't use this here or we don't get post-resolve 1-to-1 changes
			-- dq.followupFunction = "followCNAMERecords"
			dq.data.cname_chain = true
		end
	end
	return true
end

local function preresolve_override(dq)
	local fn_debug = g.options.debug_pre_override

	-- do not pre-resolve if not in our domains
	if is_excluded_from_local(dq) then
		return false
	end

	if not is_internal_domain(dq, true) then
		pdnslog(
			string.format(
				"preresolve_override(): Skipping Override for external record %s",
				dq.qname:toString()
			),
			pdns.loglevels.Debug
		)
		return false
	end

	pdnslog(
		string.format(
			"preresolve_override(): Executing Override for external record %s",
			dq.qname:toString()
		),
		pdns.loglevels.Debug
	)
	local qname = f.qname_remove_trailing_dot(dq)
	local replaced = false
	if f.table_contains_key(g.options.override_map, qname) then
		for key, value in pairs(g.options.override_map) do
			if replaced then break end
			if key == qname then
				replaced = replace_content(dq, value)
			end
		end
	end

	for key, value in pairs(g.options.regex_map) do
		if replaced then break end
		local matches = re.match(qname, key) ~= nil

		pdnslog(
			string.format(
				"%s matches %s: %s",
				qname,
				key,
				matches
			),
			pdns.loglevels.Debug
		)
		if matches then
			replaced = replace_content(dq, value)
			-- Log data
			if fn_debug then
				pdnslog(
					string.format(
						"preresolve_override(): REGEX Replaced Result: %s for"..
						" '%s' (type %s)",
						tostring(replaced),
						tostring(key),
						tostring(value.qtype)
					),
					pdns.loglevels.Debug
				)
			end
		end
	end

	if replaced then
		dq.variable = true
		if dq.data.cname_chain then
			return replaced
		end
		return postresolve(dq)
	end

	return false
end

local function preresolve_ns(dq)
	if dq.qtype ~= pdns.NS then
		return false
	end

	if not g.options.private_zones_ns_override then
		return false
	end

	if is_excluded_from_local(dq) then
		return false
	end

	-- do not pre-resolve if not in our domains
	if not is_internal_domain(dq, false) then
		pdnslog(
			string.format(
				"preresolve_ns(): Skipping NS pre-resolve for external record %s",
				dq.qname:toString()
			),
			pdns.loglevels.Debug
		)
		return false
	end

	pdnslog(
		string.format(
			"preresolve_ns(): Executing NS pre-resolve for external record %s",
			dq.qname:toString()
		),
		pdns.loglevels.Debug
	)
	local modified = false
	local override_map = g.options.private_zones_ns_override_map
	local override_prefixes = g.options.private_zones_ns_override_prefixes
	local map_only = g.options.private_zones_ns_override_map_only

	for i, domain in ipairs(local_domain_overrides_t) do
		local parent_dn = newDN(domain)

		if dq.qname:isPartOf(parent_dn) then
			local new_ns = {}
			local use_override_auto
			local use_override_map

			-- Set override auto map
			if override_prefixes and not map_only then
				use_override_auto = f.table_len(override_prefixes) > 1
			end

			-- Set override map
			if override_map then
				if f.table_len(override_map) >= 1 then
					use_override_map = f.table_contains_key(override_map, domain)
				end
			end

			if use_override_map then
				for dom, s_list in pairs(override_map) do
					-- p == prefix, d == domain
					if dom == domain then
						for i, suffix in ipairs(s_list) do
							table.insert(new_ns, suffix)
						end
						break
					end
				end
			elseif use_override_auto then
				new_ns = override_prefixes
			elseif not map_only then
				new_ns = {
					"ns1",
					"ns2",
					"dns"
				}
			end

			-- Replace Contents
			pdnslog("HERE")
			pdnslog(f.table_to_str(new_ns))
			if new_ns then
				dq.variable = true
				dq:setRecords({})
				for i, ns in ipairs(new_ns) do
					dq:addAnswer(pdns.NS, ns .. "." .. domain, 300)
					if not modified then
						modified = true
					end
				end
			end

			if modified then break end
		end
	end

	return modified
end

-- this function is hooked before resolving starts
local function preresolve_rpr(dq)
	-- do not pre-resolve if not in our domains
	if is_excluded_from_local(dq) then
		return false
	end

	-- If it's a CNAME Local Override skip this.
	if dq.data.cname_chain then
		return true
	end

	if has_conf_override(dq) then
		pdnslog(
			string.format(
				"preresolve_rpr(): Skipping reverse proxy replacement"..
				" pre-resolve for external record %s as it has an override",
				dq.qname:toString()
			),
			pdns.loglevels.Debug
		)
		return false
	end

	local exclude_main_domain_from_irp
	if g.options.exclude_main_domain_from_irp == nil then
		check_main = true
	else
		check_main = not g.options.exclude_main_domain_from_irp
	end
	if not is_internal_domain(dq, check_main)
	then
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

	local replaced = false
	if dq.qtype == pdns.A or dq.qtype == pdns.ANY then
		if g.options.internal_reverse_proxy_v4 then
			replaced = true
			dq:addAnswer(
				pdns.A,
				g.options.internal_reverse_proxy_v4,
				g.options.default_ttl
			)
		end
	end

	if dq.qtype == pdns.AAAA or dq.qtype == pdns.ANY then
		if g.options.internal_reverse_proxy_v6 then
			replaced = true
			dq:addAnswer(
				pdns.AAAA,
				g.options.internal_reverse_proxy_v6,
				g.options.default_ttl
			)
		end
	end

	if replaced then
		postresolve(dq)
	end
	return replaced
end

-- Add preresolve functions to table, ORDER MATTERS
if g.options.use_local_forwarder then
	loadDSFile(g.pdns_scripts_path.."/local-domains.list", local_domain_overrides, local_domain_overrides_t)
	if g.options.override_map or g.options.regex_map then
		mainlog("Loading preresolve_override into pre-resolve functions.", pdns.loglevels.Notice)
		f.addHookFunction("pre", "preresolve_override", preresolve_override)
	end

	if g.options.private_zones_ns_override then
		mainlog("Loading preresolve_ns into pre-resolve functions.", pdns.loglevels.Notice)
		f.addHookFunction("pre", "preresolve_ns", preresolve_ns)
	end

	if g.options.use_one_to_one then
		mainlog(
			"Loading postresolve_one_to_one into post-resolve "..
			"functions.",
			pdns.loglevels.Notice
		)
		f.addHookFunction("post", "postresolve_one_to_one", postresolve_one_to_one)
	end

	mainlog("Loading preresolve_rpr into pre-resolve functions.", pdns.loglevels.Notice)
	f.addHookFunction("pre", "preresolve_rpr", preresolve_rpr)
else
	mainlog("Local Domain Forwarder Override not enabled. Set overrides in file overrides.lua", pdns.loglevels.Notice)
end
