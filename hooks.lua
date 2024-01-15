pdns_scripts_path = "/etc/powerdns/pdns-recursor-scripts"

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

if fileExists(pdns_scripts_path.."/include.conf") then
	for line in io.lines(pdns_scripts_path.."/include.conf") do
		if string.find(line, "/") then
			local path = line
		else
			local path = pdns_scripts_path.."/"..line
		end
		if fileExists(path) then
			pdnslog("Loading Script File: " .. path, pdns.loglevels.Notice)
			loadfile(path)
		else
			pdnslog("Could not load Script File: " .. path, pdns.loglevels.Warning)
		end
	end
else
	loadfile(pdns_scripts_path.."/malware-filter.lua")
	loadfile(pdns_scripts_path.."/local-domains.lua")
end

function preresolve(dq)
	return preresolve_lo(dq) or preresolve_mf(dq)
end

function postresolve(dq)
	return postresolve_mf(dq)
end