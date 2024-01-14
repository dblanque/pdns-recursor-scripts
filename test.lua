local re
local re_pattern_adblock='^(\\|){2}(.*)\\^$' -- Matches Adblock Format
local re_chars="(.*)[$^|](.*)" -- Matches PCRE Format
local re_wild="^[*.]" -- Matches Wildcard Format

local s_test_adblock="||example.com^"
local s_test_normal="example.com"
local s_test_regex="(\\.|^)example\\.com$"
local s_test_wildcard="*.example.com"
local s_tests={
	s_test_adblock,
	s_test_normal,
	s_test_regex,
	s_test_wildcard
}

function isModuleAvailable(name)
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
if isModuleAvailable("rex_pcre") then
	re = require"rex_pcre"
elseif isModuleAvailable("rex_pcre2") then
	re = require"rex_pcre2"
else
	error("pdns-recursor-scripts malware-filter.lua requires rex_pcre or rex_pcre2 to be installed")
end

for key, line in pairs(s_tests) do
	if re.match(line, re_pattern_adblock) then -- ADBLOCK FORMAT
		local stripped = string.gsub(line, "||", "")
		stripped = string.gsub(stripped, "%^", "") -- Escape Special character ^ with %
		print("ADBLOCK: "..stripped)
	elseif re.match(line, re_chars) then -- PCRE FORMAT
		print("PCRE: "..line)
	elseif re.match(line, re_wild) then -- WILDCARD FORMAT
		local wilded = string.gsub(line, '*%.', "") -- Escape Special character . with %
		wilded = ".*\\.*"..string.gsub(wilded, '%.', "\\.") -- Escape Special Characters
		print("WILD: "..wilded)
	else -- STANDARD HOSTS FORMAT
		print("STANDARD: "..line)
	end
end
