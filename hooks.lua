-- returns true if the given file exists
function fileExists(file)
	local f = io.open(file, "rb")
	if f then
		f:close()
	end
	return f ~= nil
end

-- loads contents of a file line by line into the given table
function loadFile(filename, list)
	if fileExists(filename) then
		for line in io.lines(filename) do
			list:add(line)
		end
		pdnslog("Lua script: " .. filename .. " successfully loaded", pdns.loglevels.Notice)
	else
		pdnslog("Lua script: could not open file " .. filename, pdns.loglevels.Warning)
	end
end

function loadFileNMG(filename, list)
	if fileExists(filename) then
		for line in io.lines(filename) do
			list:addMask(line)
		end
		pdnslog("Lua script: " .. filename .. " successfully loaded", pdns.loglevels.Notice)
	else
		pdnslog("Lua script: could not open file " .. filename, pdns.loglevels.Warning)
	end
end

local function get_script_path()
	local str = debug.getinfo(1, "S").source:sub(2)
	return str:match("(.*/)") or "."
end

local script_path = get_script_path()

dofile(script_path.."/malware-filter.lua")
dofile(script_path.."/local-domains.lua")

function preresolve(dq)
	return preresolve_mf(dq) or preresolve_lo(dq)
end