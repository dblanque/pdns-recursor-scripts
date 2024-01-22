-- Do not modify this file, it's maintained by the repo.
-- Add your overrides into the conf.d directory instead 
-- (you may copy and options.lua there and modify what you want)
package.path = package.path .. ";"..g.pdns_scripts_path.."/conf.d/?.lua"

local function get_lua_modules_in_conf(search_dir)
	local files = {}
	for dir in io.popen("ls -pa " .. search_dir .. " | grep -v /|grep -E \"*(.lua)\""):lines() 
	do
		-- table.insert(files, string.gsub(dir, '%.lua', '')[0])
		table.insert(files, g.pdns_scripts_path .. '/conf.d/' .. dir)
	end
	return files
end

for index, lua_file in ipairs(get_lua_modules_in_conf(g.pdns_scripts_path .. '/conf.d')) do
	pdnslog("Loading config file: " .. lua_file, pdns.loglevels.Notice)
	dofile(lua_file)
end
