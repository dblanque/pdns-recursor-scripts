-- Do not modify this file, it's maintained by the repo.
-- Add your overrides into the conf.d directory instead 
-- (you may copy and options.lua there and modify what you want)
local conf_d_path = g.pdns_scripts_path .. '/conf.d'
local options_overrides = {}
-- package.path = package.path .. ";".. conf_d_path .. "/?.lua"

local function get_lua_modules_in_conf(search_dir, fullpath)
	local files = {}
	for dir in io.popen("ls -pa " .. search_dir .. " | grep -v /|grep -E \"*(.lua)\""):lines() 
	do
		if fullpath then
			table.insert(files, conf_d_path .. "/" .. dir)
		else
			table.insert(files, string.gsub(dir, '%.lua', '')[0])
		end
	end
	return files
end

local conf_files = get_lua_modules_in_conf(conf_d_path, true)
local conf_files_l = table_len(conf_files)

for index, lua_file in ipairs(conf_files) do
	pdnslog("Loading config file: " .. lua_file, pdns.loglevels.Notice)
	dofile(filename)

	if index >= conf_files_l then
		pdnslog("Table Length: "..table_len(options_overrides), pdns.loglevels.Notice)
		return options_overrides
	end
end
