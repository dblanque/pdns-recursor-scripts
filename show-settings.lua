
function script_path()
	local str = debug.getinfo(2, "S").source:sub(2)
	return str:match("(.*/)") or "."
end

local function pdnslog(msg, loglevel)
	-- Stub function
	print(msg)
end

g = {}
f = require('functions')
g.pdns_scripts_path = script_path()
g.options = require('defaults')
g.options_overrides = require('overrides-handler')
package.path = package.path .. ";"..g.pdns_scripts_path.."/?.lua"
if not g.options_overrides then
	pdnslog("Could not import overrides correctly (or there are none).")
else
	for k, v in pairs(g.options_overrides) do
		if type(v) ~= 'table' then
			pdnslog("Loaded Option (".. tostring(k) .."): "..tostring(v))
		else
			pdnslog("Loaded Option (".. tostring(k) .."): "..tostring(v))
			for index, value in pairs(v) do
				pdnslog(index, value)
			end
		end
		g.options[k] = v
	end
	pdnslog("Loaded ".. f.table_len(g.options_overrides) .." overrides")
end
