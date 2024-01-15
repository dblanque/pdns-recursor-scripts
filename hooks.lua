-- Set package path
g={}
g.preresolve_index = {}
g.postresolve_index = {}
g.preresolve_functions = {}
g.postresolve_functions = {}
g.pdns_scripts_path = "/etc/powerdns/pdns-recursor-scripts"
package.path = package.path .. ";"..g.pdns_scripts_path.."/?.lua"

g.options = require 'options'
local options_overrides = require 'overrides'
for k, v in pairs(options_overrides) do
	g.options[k] = v
end

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

function table_index (tab, val)
	for index, value in ipairs(tab) do
		if value == val then
			return index
		end
	end
	return nil
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

require("local-domains")
require("malware-filter")

pdnslog("preresolve function table contains "..table_len(g.preresolve_functions).." entries.", pdns.loglevels.Notice)
pdnslog("postresolve function table contains "..table_len(g.postresolve_functions).." entries.", pdns.loglevels.Notice)
for i,k in ipairs(g.preresolve_index) do
	pdnslog(k.." preresolve function loaded.", pdns.loglevels.Notice)
end
for i,k in ipairs(g.postresolve_index) do
	pdnslog(k.." postresolve function loaded.", pdns.loglevels.Notice)
end

function preresolve(dq)
	for i,k in ipairs(g.preresolve_index) do
		local f = g.postresolve_functions[k]
		pdnslog("preresolve f(): "..k, pdns.loglevels.Notice)
		local result = f(dq)
		if result == true then return result end
	end
	return false
end

function postresolve(dq)
	for i,k in ipairs(g.postresolve_index) do
		local f = g.postresolve_functions[k]
		pdnslog("postresolve f(): "..k, pdns.loglevels.Notice)
		local result = f(dq)
		if result == true then return result end
	end
	return false
end