-- Do not modify this file, it's maintained by the repo.
-- Add your overrides into the conf.d directory instead 
-- (you may copy and options.lua there and modify what you want)
local conf_d_path = g.pdns_scripts_path .. '/conf.d'

local function get_lua_modules_in_conf(search_dir, fullpath)
	local files = {}
	for dir in io.popen("ls -pa " .. search_dir .. " | grep -v /|grep -E \"*(.lua)\""):lines() 
	do
		if fullpath then
			table.insert(files, conf_d_path .. "/" .. dir)
		else
			table.insert(files, string.gsub(dir, '%.lua', ''))
		end
	end
	return files
end

local conf_files = get_lua_modules_in_conf(conf_d_path, true)
for index, lua_file in ipairs(conf_files) do
	dofile(lua_file)
end
