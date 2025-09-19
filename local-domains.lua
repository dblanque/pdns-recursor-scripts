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
require "pdns-constants"
require "resolve-cname-chain"

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

function valid_type_replace_for_cname(dq_type, replace_type)
	local types_match = dq_type == replace_type
	local valid_type_replaces = (
		f.table_contains(SUPPORTED_CNAME_TARGET, REVERSE_QTYPES[dq_type])
		and replace_type == pdns.CNAME
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
		if g.options.debug_post_one_to_one then
			f.dr_log_content(record_content)
		end
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

-- Adds local override content to a Domain Question.
-- @param dq userdata
-- @param dq_override table of { qtype=string, content=table }
-- @return bool
local function add_content(dq, dq_override, qname_override)
	-- Top level Query Name
	local qname = qname_override or dq.qname:toString()

	-- dr: Domain Record
	local dr_type = dq_override.qtype
	local dr_replace_any = dq_override.replace_any
	local function can_replace(source_qtype, target_qtype)
		if (
			not valid_type_replace_for_cname(source_qtype, target_qtype) and
			not dr_replace_any
		) then
			return false
		end
		return true
	end

	if not can_replace(dq.qtype, pdns[dr_type]) then
		return false
	end

	local dr_values = dq_override.content
	local dr_ttl = dq_override.ttl or g.options.default_ttl
	local sub_dr = nil

	for i, dr_override in ipairs(dr_values) do
		-- If it's a CNAME Replacement, only allow one value.
		if pdns[dr_type] == pdns.CNAME then
			-- Don't use this here or we don't get post-resolve 1-to-1 changes
			-- dq.followupFunction = "followCNAMERecords"

			-- Add answer with previous CNAME in chain or main qname
			dq:addRecord(
				pdns[dr_type], dr_override, 1, dr_ttl, dr_values[i-1] or qname)
				-- Type, Value, Place, TTL, Name
			dq.data.cname_chain = true

			-- Check if there are local cname overrides, add them as well.
			if f.table_contains_key(g.options.override_map, dr_override) then
				for key, value in pairs(g.options.override_map) do
					if key == dr_override and can_replace(dq.qtype, pdns[value.qtype])
					then
						sub_dr = value
						break
					end
				end
			end

			for key, value in pairs(g.options.regex_map) do
				if sub_dr then break end
				local matches = re.match(dr_override, key)
				if matches and can_replace(dq.qtype, pdns[value.qtype]) then
					sub_dr = value
				end
			end

			if g.options.cname_resolver_enabled then
				if sub_dr then
					-- Add local cname overrides recursively.
					add_content(dq, sub_dr, dr_override)
				else
					--[[
						We need to do this with dig instead of PowerDNS's
						native followupFunction "FollowCNAMERecords" as it
						does not support postresolve execution once the
						result has been modified in a preresolve function.
					]]
					follow_cname_chain(dq, qname, dr_override)
				end
			end
		else
			-- Add answer
			dq:addAnswer(pdns[dr_type], dr_override, dr_ttl) -- Type, Value, TTL
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
				replaced = add_content(dq, value)
			end
		end
	end

	for key, value in pairs(g.options.regex_map) do
		if replaced then break end
		local matches = re.match(qname, key) ~= nil

		if fn_debug then
			pdnslog(
				string.format(
					"preresolve_override(): %s matches %s: %s",
					qname,
					key,
					matches
				),
				pdns.loglevels.Debug
			)
		end
		if matches then
			replaced = add_content(dq, value)
		end
	end

	if replaced then
		dq.variable = true
		-- if dq.data.cname_chain then
		-- 	return replaced
		-- end
		return postresolve(dq)
	end

	return false
end

-- this function is hooked before resolving starts
local function preresolve_rpr(dq)
	-- do not pre-resolve if not in our domains
	if is_excluded_from_local(dq) then
		return false
	end

	-- If it's a CNAME override or has any type of local override skip this.
	if dq.data.cname_chain or has_conf_override(dq) then
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
	-- Pre-resolve functions
	if g.options.override_map or g.options.regex_map then
		mainlog("Loading preresolve_override into pre-resolve functions.", pdns.loglevels.Notice)
		f.addHookFunction("pre", "preresolve_override", preresolve_override)
	end

	mainlog("Loading preresolve_rpr into pre-resolve functions.", pdns.loglevels.Notice)
	f.addHookFunction("pre", "preresolve_rpr", preresolve_rpr)

	-- Post-resolve functions
	if g.options.use_one_to_one then
		mainlog(
			"Loading postresolve_one_to_one into post-resolve "..
			"functions.",
			pdns.loglevels.Notice
		)
		f.addHookFunction("post", "postresolve_one_to_one", postresolve_one_to_one)
	end

else
	mainlog("Local Domain Forwarder Override not enabled. Set overrides in file overrides.lua", pdns.loglevels.Notice)
end
