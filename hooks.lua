-- Set package path
g={}
g.preresolve_index = {}
g.postresolve_index = {}
g.preresolve_functions = {}
g.postresolve_functions = {}
g.pdns_scripts_path = "/etc/powerdns/pdns-recursor-scripts"
package.path = package.path .. ";"..g.pdns_scripts_path.."/?.lua"

-- Required for load-order based execution
function addResolveFunction(mode, f_name, f)
	local t_i
	local t_f
	if mode == "pre" then
		t_i = "preresolve_index"
		t_f = "preresolve_functions"
	elseif mode == "post" then
		t_i = "postresolve_index"
		t_f = "postresolve_functions"
	else
		error("addResolveFunction(): mode param must be 'pre' or 'post'")
	end
	table.insert(g[t_i], f_name)
	g[t_f][f_name] = f
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

function table_contains(tab, val, has_keys)
	if has_keys then
		for k, v in pairs(tab) do
			if v == val then
				return true
			end
		end
	else
		for i, v in ipairs(tab) do
			if v == val then
				return true
			end
		end
	end
	return false
end

function table_contains_key(tab, key)
	if tab[key] ~= nil then return true end
	return false
	-- for k, v in pairs(tab) do
	-- 	if k == key then
	-- 		return true
	-- 	end
	-- end
	-- return false
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

-- src: https://stackoverflow.com/questions/1426954/split-string-in-lua
function string_split(inputstr, sep)
	if sep == nil then
			sep = "%s"
	end
	local t={}
	for str in string.gmatch(inputstr, "([^"..sep.."]+)") do
			table.insert(t, str)
	end
	return t
end

function qname_remove_trailing_dot(dq)
	return string.sub(tostring(dq.qname), 1, -2)
end

-- returns true if the given file exists
function fileExists(file)
	local f = io.open(file, "rb")
	if f then
		f:close()
	end
	return f ~= nil
end

g.options = require('defaults')
g.options_overrides = require('overrides-handler')
if not g.options_overrides then
	pdnslog("Could not import hooks.lua overrides correctly", pdns.loglevels.Error)
end
for k, v in pairs(g.options_overrides) do
	g.options[k] = v
end

require("local-domains")
require("malware-filter")

pdnslog("preresolve function table contains "..table_len(g.preresolve_functions).." entries.", pdns.loglevels.Notice)
pdnslog("postresolve function table contains "..table_len(g.postresolve_functions).." entries.", pdns.loglevels.Notice)
for i, k in ipairs(g.preresolve_index) do
	pdnslog(k.." preresolve function loaded.", pdns.loglevels.Notice)
end
for i, k in ipairs(g.postresolve_index) do
	pdnslog(k.." postresolve function loaded.", pdns.loglevels.Notice)
end

function preresolve(dq)
	for index, f_name in ipairs(g.preresolve_index) do
		local f = g.preresolve_functions[f_name]
		if not f then
			pdnslog("preresolve f() Function Index Mis-match: "..f_name, pdns.loglevels.Warning)
			goto continue
		end
		-- pdnslog("preresolve f(): "..f_name, pdns.loglevels.Notice)
		local result = f(dq)
		if result == true then return result end
		::continue::
	end
	return false
end

function postresolve(dq)
	for index, f_name in ipairs(g.postresolve_index) do
		local f = g.postresolve_functions[f_name]
		if not f then
			pdnslog("postresolve f() Function Index Mis-match: "..f_name, pdns.loglevels.Warning)
			goto continue
		end
		-- pdnslog("postresolve f(): "..f_name, pdns.loglevels.Notice)
		local result = f(dq)
		if result == true then return result end
		::continue::
	end
	return false
end