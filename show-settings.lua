
function script_path()
	local str = debug.getinfo(2, "S").source:sub(2)
	return str:match("(.*/)") or "."
end

g = {}
f = require('functions')
g.pdns_scripts_path = script_path()
g.options = require('defaults')
g.options_overrides = require('overrides-handler')
package.path = package.path .. ";"..g.pdns_scripts_path.."/?.lua"
if not g.options_overrides then
	print("Could not import overrides correctly (or there are none).")
else
	for k, v in pairs(g.options_overrides) do
		print("Loaded Option (".. tostring(k) .."): "..tostring(v))
		g.options[k] = v
	end
	print("Loaded ".. f.table_len(g.options_overrides) .." overrides")
end
