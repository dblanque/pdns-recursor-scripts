pdns_scripts_path = "/etc/powerdns/pdns-recursor-scripts"

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
		pdnslog("Lua script: " .. filename .. " successfully loaded", pdns.loglevels.Notice)
	else
		pdnslog("Lua script: could not open file " .. filename, pdns.loglevels.Warning)
	end
end

dofile(pdns_scripts_path.."/malware-filter.lua")
dofile(pdns_scripts_path.."/local-domains.lua")

function preresolve(dq)
	return preresolve_mf(dq) or preresolve_lo(dq)
end