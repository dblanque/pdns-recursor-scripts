-- Set package path
g = {}
g.maintenance_index = {}
g.preresolve_index = {}
g.postresolve_index = {}
g.maintenance_functions = {}
g.preresolve_functions = {}
g.postresolve_functions = {}
g.pdns_scripts_path = "/etc/powerdns/pdns-recursor-scripts"
g.recursor_thread_id = getRecursorThreadId()
g.initialized_mf = false
package.path = package.path .. ";"..g.pdns_scripts_path.."/?.lua"

function mainlog(msg, level)
	if g.recursor_thread_id == 1 then
		pdnslog(msg, level)
	end
end

f = require('functions')
g.options = require('defaults')
g.options_overrides = require('overrides-handler')
if not g.options_overrides then
	mainlog(
		"Could not import overrides correctly (or there are none).",
		pdns.loglevels.Error
	)
else
	for k, v in pairs(g.options_overrides) do
		mainlog(
			"Loaded Option (".. tostring(k) .."): "..tostring(v),
			pdns.loglevels.Debug
		)
		g.options[k] = v
	end
	mainlog(
		string.format(
			"Loaded %d overrides",
			f.table_len(g.options_overrides)
		),
		pdns.loglevels.Notice
	)
end

require("local-domains")
require("malware-filter")

mainlog(
	string.format(
		"preresolve function table contains %d entries.",
		f.table_len(g.preresolve_functions)
	),
	pdns.loglevels.Notice
)
mainlog(
	string.format(
		"postresolve function table contains %d entries.",
		f.table_len(g.postresolve_functions)
	),
	pdns.loglevels.Notice
)
for i, k in ipairs(g.preresolve_index) do
	mainlog(k.." preresolve function added.", pdns.loglevels.Debug)
end
for i, k in ipairs(g.postresolve_index) do
	mainlog(k.." postresolve function added.", pdns.loglevels.Debug)
end

function preresolve(dq)
	-- Initialize persistent data table
	if not dq.data then
		dq.data = {}
	end
	local result = false

	for index, f_name in ipairs(g.preresolve_index) do
		local pre_r_f = g.preresolve_functions[f_name]
		if not pre_r_f then
			pdnslog(
				"preresolve f() Function Index Mis-match: " .. f_name,
				pdns.loglevels.Warning
			)
			goto continue
		end
		pdnslog("preresolve f(): " .. f_name, pdns.loglevels.Debug)
		result = pre_r_f(dq)
		if result then
			pdnslog("preresolve f(): Returned true for " .. f_name, pdns.loglevels.Debug)
			dq.variable = true
			-- Log Content
			f.dq_log_record_content(dq)
			break
		end
		::continue::
	end
	if result then return result end
	pdnslog(
		"DQ Wants Post-resolve: " .. tostring(dq.data.cname_chain),
		pdns.loglevels.Debug
	)

	-- Patch CNAME/NS Overrides
	if dq.data.cname_chain then
		dq.variable = true

		if cname_override_patch(dq) then
			pdnslog("Applying CNAME/NS Patch", pdns.loglevels.Debug)
			return true
		end
	end

	f.dq_log_record_content(dq)
	pdnslog("Returned false on preresolve", pdns.loglevels.Debug)
	return false
end

function postresolve(dq)
	local result
	for index, f_name in ipairs(g.postresolve_index) do
		local post_r_f = g.postresolve_functions[f_name]
		if not post_r_f then
			pdnslog(
				"postresolve f() Function Index Mis-match: " .. f_name,
				pdns.loglevels.Warning
			)
			goto continue
		end
		pdnslog("postresolve f(): " .. f_name, pdns.loglevels.Debug)
		result = post_r_f(dq)
		if result then
			dq.variable = true
			return result
		end
		::continue::
	end
	return result
end

function maintenance(dq)
	if #g.maintenance_index < 1 then
		return
	end

	for index, f_name in ipairs(g.maintenance_index) do
		local maintenance_r_f = g.maintenance_functions[f_name]
		if not maintenance_r_f then
			mainlog(
				"maintenance f() Function Index Mis-match: " .. f_name,
				pdns.loglevels.Warning
			)
			goto continue
		end
		-- mainlog("maintenance f(): " .. f_name, pdns.loglevels.Debug)
		local result = maintenance_r_f(dq)
		if result == true then return result end
		::continue::
	end
	return false
end
