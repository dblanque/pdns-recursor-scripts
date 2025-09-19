--- resolve-dns.lua
local dig_validated = false
local dig_err_msg = [[
'dig' command not found. Please install BIND tools:
- Ubuntu/Debian:   sudo apt install dnsutils
- RHEL/CentOS/Fedora: sudo yum install bind-utils OR sudo dnf install bind-utils
- macOS:           brew install bind
- Windows:         Install via WSL or BIND for Windows (https://www.isc.org/bind/)
]]

local function validate_dig()
	if dig_validated then return end

	-- Try to run 'dig -v' to check availability
	local handle = io.popen("dig -v 2>/dev/null")
	if not handle then
		error(dig_err_msg)
	end
	dig_validated = true
end
validate_dig()

function log_resolve_dns_responses(responses)
	for _, r in ipairs(responses) do
		pdnslog(
			string.format(
				"Answer: %s %s %s",
				r.type,
				r.ttl,
				r.response
			)
		)
	end
end

--- Resolves DNS records with TTL and optional custom DNS server.
-- @param hostname string (e.g., "example.com")
-- @param record_type string (e.g., "A", "TXT", "MX") — default "A"
-- @param dns_server string (optional, e.g., "8.8.8.8")
-- @return table of { name=string, type=string, ttl=number, response=string }
function resolve_dns(hostname, record_type, dns_server, dns_port)
	if not dig_validated then
		return {}
	end

	record_type = record_type or "A"
	local records = {}
	local seen_cnames = {}
	local current_target = hostname

	-- Build server part: if provided, use @server
	local server_arg = dns_server and ("@" .. dns_server) or ""
	local port_arg = dns_port and ("-p " .. tostring(dns_port)) or ""

	--[[
		We need re-tries and a timeout setting to avoid PowerDNS Lockups on
		initial Resolution for CNAME chains with local overrides.
	]]
	local dig_args = "+noall +answer +timeout=3 +tries=3 +ttl"

	while true do
		-- We use +noall +answer +ttl to get structured output with TTL
		local cmd = string.format("dig %s %s %s %s %s",
				dig_args, server_arg, port_arg, record_type, current_target)

		if pdns then
			pdnslog(cmd, pdns.loglevels.Debug)
		end

		local handle = io.popen(cmd)
		if not handle then
			error("Failed to execute dig: " .. cmd)
		end

		local output = handle:read("*a")
		handle:close()

		if not output then break end

		local lines = {}
		for line in output:gmatch("[^\r\n]+") do
			line = line:gsub("^%s*(.-)%s*$", "%1")  -- trim
			if line ~= "" and not line:find("^;") then
				table.insert(lines, line)
			end
		end

		if #lines == 0 then break end

		-- Parse each line: [name] [ttl] [class] [type] [rdata...]
		-- Example: example.com. 300 IN A 192.0.2.1
		-- Example: example.com. 3600 IN TXT "v=spf1" "include:..."
		local parsed_lines = {}
		local cname_found = nil

		for _, line in ipairs(lines) do
			-- Match: <name> <ttl> IN <type> <data...>
			local name, ttl, class, rtype, rdata = 
				line:match("^([^%s]+)%s+(%d+)%s+([A-Z]+)%s+([A-Z0-9_]+)%s+(.+)$")

			-- pdnslog("name: "..name)
			-- pdnslog("ttl: "..ttl)
			-- pdnslog("class: "..class)
			-- pdnslog("rtype: "..rtype)
			-- pdnslog("rdata: "..rdata)
			if not rtype then
				-- Skip malformed/unparsed lines
				goto continue
			end

			-- Normalize: remove trailing dot from name if present (optional)
			-- We don’t need name unless validating — we care about type and data
			ttl = tonumber(ttl)
			rdata = rdata or ""

			-- If this is a CNAME and we’re not explicitly querying CNAME
			if rtype == "CNAME" and record_type ~= "CNAME" then
				cname_found = rdata
			end

			-- Handle TXT records: may be split into multiple quoted strings
			if rtype == "TXT" then
				local txt_parts = {}
				for part in rdata:gmatch('("[^"]*")') do
					-- remove surrounding quotes
					table.insert(txt_parts, part:sub(2, -2))
				end
				rdata = table.concat(txt_parts, "")
			end

			table.insert(parsed_lines, {
				name = name,
				type = rtype,
				ttl = ttl,
				response = rdata
			})

			::continue::
		end

		-- If we found a CNAME and we’re following chain
		-- (not explicitly querying CNAME)
		if cname_found and record_type ~= "CNAME" then
			-- Record the CNAME
			for _, rec in ipairs(parsed_lines) do
				if rec.type == "CNAME" then
					table.insert(records, rec)
				end
			end

			-- Infinite loop breaker
			if seen_cnames[cname_found] then
				break
			end
			seen_cnames[cname_found] = true
			current_target = cname_found
		else
			-- Add all records
			for _, rec in ipairs(parsed_lines) do
				table.insert(records, rec)
			end
			break
		end
	end

	return records
end
