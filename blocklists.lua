
local function script_path()
	local str = debug.getinfo(1, "S").source:sub(2)
	return str:match("(.*/)") or "."
end

local function get_list_files_in_dir(search_dir)
	local files = {}
	for dir in io.popen("ls -pa "..search_dir.." | grep -v /|grep -E \"*.list\""):lines() 
	do
		table.insert(files, script_path().."/"..dir)
	end
	return files
end

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
	end
end

local dnsbl_file_table = get_list_files_in_dir(script_path().."/dnsbl.d")
local dnsbl = {}
local ipbl_file_table = get_list_files_in_dir(script_path().."/ipbl.d")
local ipbl = {}

for k, v in pairs(dnsbl_file_table)
do
	print(k, v)
end

for k, v in pairs(ipbl_file_table)
do
	loadFile(v, ipbl)
end

for k,v in pairs(ipbl)
do
	print(v)
end
