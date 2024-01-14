
s_test_adblock="||example.com^"
s_test_normal="example.com"
s_test_regex="(\\.|^)example\\.com$"
s_test_wildcard="*.example.com"

if re.match(line, re_pattern_adblock) then -- ADBLOCK FORMAT
	local stripped = string.gsub(line, "||", "")
	stripped = string.gsub(stripped, "%^", "") -- Escape Special character ^ with %
	dnsbl_list:add(stripped)
elseif re.match(line, re_chars) then -- PCRE FORMAT
	table.insert(rebl_list, line)
elseif re.match(line, re_wild) then -- WILDCARD FORMAT
	local wilded = string.gsub(line, '*%.', "") -- Escape Special character . with %
	wilded = ".*\\.*"..string.gsub(wilded, '%.', "\\.") -- Escape Special Characters
	table.insert(wildbl_list, wilded)
else -- STANDARD HOSTS FORMAT
	dnsbl_list:add(line)
end
