local f = {}

-- Required for load-order based execution
function f.addResolveFunction(mode, f_name, f)
	local t_i
	local t_f
	if mode == "pre" then
		t_i = "preresolve_index"
		t_f = "preresolve_functions"
	elseif mode == "post" then
		t_i = "postresolve_index"
		t_f = "postresolve_functions"
	else
		error("addResolveFunction(): mode param must be 'pre' or 'post'")
	end
	table.insert(g[t_i], f_name)
	g[t_f][f_name] = f
end

function f.isModuleAvailable(name)
	if package.loaded[name] then
		return true
	else
		for _, searcher in ipairs(package.searchers or package.loaders) do
			local loader = searcher(name)
			if type(loader) == 'function' then
				package.preload[name] = loader
				return true
			end
		end
		return false
	end
end

function f.empty_str(s)
	return s == nil or s == ''
end

function f.table_contains(tab, val, has_keys)
	if has_keys then
		for k, v in pairs(tab) do
			if v == val then
				return true
			end
		end
	else
		for i, v in ipairs(tab) do
			if v == val then
				return true
			end
		end
	end
	return false
end

function f.table_contains_key(tab, key)
	if tab[key] ~= nil then return true end
	return false
	-- for k, v in pairs(tab) do
	-- 	if k == key then
	-- 		return true
	-- 	end
	-- end
	-- return false
end

function f.table_len(T)
	local count = 0
	for _ in pairs(T) do count = count + 1 end
	return count
  end

-- This function uses native LUA Regex, not PCRE2
function f.is_comment(v)
	if not v then return false end
	local p_list = {
		"^ *#(.*)$",
		"^ *%-%-(.*)$",
		"^ *//(.*)$",
		"^ *!(.*)$"
	}
	for key, pattern in pairs(p_list) do
		if string.match(v, pattern) then return true end
	end
	return false
end

-- src: https://stackoverflow.com/questions/1426954/split-string-in-lua
function f.string_split(inputstr, sep)
	if sep == nil then
			sep = "%s"
	end
	local t={}
	for str in string.gmatch(inputstr, "([^"..sep.."]+)") do
			table.insert(t, str)
	end
	return t
end

function f.qname_remove_trailing_dot(dq)
	if string.sub(tostring(dq.qname), -1) == "." then
		return tostring(string.sub(tostring(dq.qname), 1, -2))
	end
	return tostring(dq.qname)
end

-- returns true if the given file exists
function f.fileExists(file)
	local f = io.open(file, "rb")
	if f then
		f:close()
	end
	return f ~= nil
end

return f