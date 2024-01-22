-- Do not modify this file, it's maintained by the repo.
-- Add your overrides into the conf.d directory instead 
-- (you may copy and paste this file or options.lua there and modify what you want)
local options_overrides = {
}

local function get_lua_modules_in_conf(search_dir)
	local files = {}
	for dir in io.popen("ls -pa " .. search_dir .. " | grep -v /|grep -E \"*(.lua)\""):lines() 
	do
		table.insert(files, string.gsub(dir, '%.lua', ''))
	end
	return files
end

for index, lua_file in ipairs(get_lua_modules_in_conf(g.pdns_scripts_path)) do
	require(lua_file)
end

return options_overrides