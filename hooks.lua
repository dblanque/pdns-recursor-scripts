-- Set package path
g = {}
g.preresolve_index = {}
g.postresolve_index = {}
g.preresolve_functions = {}
g.postresolve_functions = {}
g.pdns_scripts_path = "/etc/powerdns/pdns-recursor-scripts"
package.path = package.path .. ";"..g.pdns_scripts_path.."/?.lua"

f = require('functions')
g.options = require('defaults')
g.options_overrides = require('overrides-handler')
if not g.options_overrides then
	pdnslog("Could not import overrides correctly (or there are none).", pdns.loglevels.Error)
else
	for k, v in pairs(g.options_overrides) do
		pdnslog("Loaded Option (".. tostring(k) .."): "..tostring(v), pdns.loglevels.Debug)
		g.options[k] = v
	end
	pdnslog("Loaded ".. f.table_len(g.options_overrides) .." overrides", pdns.loglevels.Notice)
end

require("local-domains")
require("malware-filter")

pdnslog("preresolve function table contains ".. f.table_len(g.preresolve_functions) .. " entries.", pdns.loglevels.Notice)
pdnslog("postresolve function table contains ".. f.table_len(g.postresolve_functions) .. " entries.", pdns.loglevels.Notice)
for i, k in ipairs(g.preresolve_index) do
	pdnslog(k.." preresolve function loaded.", pdns.loglevels.Debug)
end
for i, k in ipairs(g.postresolve_index) do
	pdnslog(k.." postresolve function loaded.", pdns.loglevels.Debug)
end

function preresolve(dq)
	for index, f_name in ipairs(g.preresolve_index) do
		local pre_r_f = g.preresolve_functions[f_name]
		if not pre_r_f then
			pdnslog("preresolve f() Function Index Mis-match: "..f_name, pdns.loglevels.Warning)
			goto continue
		end
		-- pdnslog("preresolve f(): "..f_name, pdns.loglevels.Notice)
		local result = pre_r_f(dq)
		if result == true then return result end
		::continue::
	end
	return false
end

function postresolve(dq)
	for index, f_name in ipairs(g.postresolve_index) do
		local post_r_f = g.postresolve_functions[f_name]
		if not post_r_f then
			pdnslog("postresolve f() Function Index Mis-match: "..f_name, pdns.loglevels.Warning)
			goto continue
		end
		-- pdnslog("postresolve f(): "..f_name, pdns.loglevels.Notice)
		local result = post_r_f(dq)
		if result == true then return result end
		::continue::
	end
	return false
end