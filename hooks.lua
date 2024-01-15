-- Set package path
pdns_scripts_path = "/etc/powerdns/pdns-recursor-scripts"
package.path = package.path .. ";"..pdns_scripts_path.."/?.lua"

local options = require 'options'
local options_overrides = require 'overrides'
for k, v in pairs(options_overrides) do
	options[k] = v
end

preresolve_functions = {}
postresolve_functions = {}

function isModuleAvailable(name)
	if package.loaded[name] then
		return true
	else
		for _, searcher in ipairs(package.searchers or package.loaders) do
			local loader = searcher(name)
			if type(loader) == 'function' then
				package.preload[name] = loader
				return true
			end
		end
		return false
	end
end

function empty_str(s)
	return s == nil or s == ''
end

function table_contains (tab, val)
	for index, value in ipairs(tab) do
		if value == val then
			return true
		end
	end
	return false
end

function table_len(T)
	local count = 0
	for _ in pairs(T) do count = count + 1 end
	return count
  end
  
-- This function uses native LUA Regex, not PCRE2
function is_comment(v)
	if not v then return false end
	local p_list = {
		"^ *#(.*)$",
		"^ *%-%-(.*)$",
		"^ *//(.*)$",
		"^ *!(.*)$"
	}
	for key, pattern in pairs(p_list) do
		if string.match(v, pattern) then return true end
	end
	return false
end

-- returns true if the given file exists
function fileExists(file)
	local f = io.open(file, "rb")
	if f then
		f:close()
	end
	return f ~= nil
end

-- loads contents of a file line by line into the given table
function loadDSFile(filename, list)
	if fileExists(filename) then
		for line in io.lines(filename) do
			list:add(line)
		end
		pdnslog("loadDSFile(): " .. filename .. " successfully loaded", pdns.loglevels.Notice)
	else
		pdnslog("loadDSFile(): could not open file " .. filename, pdns.loglevels.Warning)
	end
end

if options.use_dnsbl or options.use_ipbl then
	dofile(pdns_scripts_path.."/malware-filter.lua")
end
if options.use_local_forwarder then
	dofile(pdns_scripts_path.."/local-domains.lua")
end

pdnslog("preresolve function table contains "..table_len(preresolve_functions).." entries.", pdns.loglevels.Notice)
pdnslog("postresolve function table contains "..table_len(postresolve_functions).." entries.", pdns.loglevels.Notice)
for k,f in pairs(preresolve_functions) do
	pdnslog(f.." preresolve function loaded.", pdns.loglevels.Notice)
end
for k,f in pairs(postresolve_functions) do
	pdnslog(f.." postresolve function loaded.", pdns.loglevels.Notice)
end

function preresolve(dq)
	for k,f in pairs(preresolve_functions) do
		local result = f(dq)
		if result then return result end
	end
	return false
end

function postresolve(dq)
	for k,f in pairs(postresolve_functions) do
		local result = f(dq)
		if result then return result end
	end
	return false
end