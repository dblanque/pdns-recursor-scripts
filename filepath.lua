-- filepath.lua
function get_realpath(p)
    local handle = io.popen("realpath "..p)
    local result = handle:read("*a")
    handle:close()
    return tostring(result:gsub("[\r\n]", ""))
end

function get_working_directory()
    local handle = io.popen("pwd")
    local result = handle:read("*a")
    handle:close()
    return tostring(result:gsub("[\r\n]", ""))
end

function script_path()
   local str = debug.getinfo(2, "S").source:sub(2)
   return get_realpath(str:match("(.*/)") or get_working_directory())
end
