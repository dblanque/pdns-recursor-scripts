local re
local re_pattern_adblock='^(\\|){2}(.*)\\^$' -- Matches Adblock Format
local re_chars="(.*)[$^|](.*)" -- Matches PCRE Format
local re_wild="^[*.]" -- Matches Wildcard Format
local re_hosts="^(0.0.0.0|::|2001:1::1)\\s+.*" -- Matches HOSTS Format

local s_test_adblock="||example-dom.com^"
local s_test_normal="example-dom.com"
local s_test_regex="(\\.|^)example-dom\\.com$"
local s_test_hosts_4="0.0.0.0 example.com"
local s_test_hosts_6=":: example.com"
local s_test_hosts_6_sink="2001:1::1 example.com"
local s_test_wildcard="*.example-dom.com"
local s_tests={
	s_test_adblock,
	s_test_normal,
	s_test_regex,
	s_test_hosts_4,
	s_test_hosts_6,
	s_test_hosts_6_sink,
	s_test_wildcard,
}
local test_val="mail.example-dom.com"

local function script_path()
	local str = debug.getinfo(2, "S").source:sub(2)
	return str:match("(.*/)") or "."
end

g = {}
f = require('functions')
g.pdns_scripts_path = script_path()
g.options = require('defaults')
g.options_overrides = require('overrides-handler')
package.path = package.path .. ";"..g.pdns_scripts_path.."/?.lua"
if f.isModuleAvailable("rex_pcre") then
	re = require"rex_pcre"
elseif f.isModuleAvailable("rex_pcre2") then
	re = require"rex_pcre2"
else
	error("pdns-recursor-scripts malware-filter.lua requires rex_pcre or rex_pcre2 to be installed")
end

for key, line in pairs(s_tests) do
	if re.match(line, re_pattern_adblock) then -- ADBLOCK FORMAT
		local stripped = string.gsub(line, "||", "")
		stripped = string.gsub(stripped, "%^", "") -- Escape Special character ^ with %
		print("ADBLOCK: ".." (Index: "..key..") | \""..stripped.."\"")
	elseif re.match(line, re_chars) then -- PCRE FORMAT
		print("PCRE: ".." (Index: "..key..") | \""..line.."\"")
	elseif re.match(line, re_wild) then -- WILDCARD FORMAT
		local wilded = string.gsub(line, '*%.', "") -- Escape Special character . with %
		wilded = ".*\\.*?"..string.gsub(wilded, '%.', "\\.")
		print("WILD: ".." (Index: "..key..") | \""..wilded.."\"")
		test_re = wilded
	elseif re.match(line, re_hosts) then
		local domain = f.extract_hosts_domain(line)
		print("HOSTS: ".." (Index: "..key..") | \""..domain.."\"")
	else -- STANDARD HOSTS FORMAT
		print("STANDARD: ".." (Index: "..key..") | \""..line.."\"")
	end
end

if re.match(test_val, test_re) then
	print("Test Wildcard Regex Matched")
else
	print("Test Wildcard Regex was not Matched")
end