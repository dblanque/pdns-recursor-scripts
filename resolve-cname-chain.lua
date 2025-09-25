require "resolve-dns"
require "pdns-constants"

--- Adds DNS Answers for full CNAME Chain Resolution.
-- @param dq userdata
-- @param chain_result table of { name=string, type=string, ttl=number, response=string }
-- @return bool
local function add_chain_answers(dq, chain_result)
	if not chain_result then
		pdnslog("No chain result for content replace.", pdns.loglevels.Debug)
		return
	end

	for _, r in ipairs(chain_result) do
		local rtype = pdns[r.type]
		if not rtype then
			goto continue
		end
		dq:addRecord(rtype, r.response, 1, r.ttl, r.name)
		::continue::
	end

	if #chain_result >= 1 then
		return true
	end
	return false
end

-- Mutates dq with CNAME answers if available
-- @param dq userdata
-- @param qname string
-- @param last_cname string
-- @return nil
function follow_cname_chain(dq, qname, last_cname)
	local qtype = REVERSE_QTYPES[dq.qtype]
	local cname_resolver_address = g.options.cname_resolver_address or "127.0.0.1"
	local cname_resolver_port = tonumber(g.options.cname_resolver_port) or 53
	local records = dq:getRecords()
	local last_cname = records[#records]:getContent()

	-- Follow last CNAME in Chain
	pdnslog(
		string.format(
			"Following CNAME (%s) Chain with %s",
			qtype,
			last_cname
		),
		pdns.loglevels.Debug
	)
	chain_responses = resolve_dns(
		last_cname,
		qtype,
		cname_resolver_address,
		cname_resolver_port
	)
	log_resolve_dns_responses(chain_responses)
	if not add_chain_answers(dq, chain_responses) then
		dq.rcode = pdns.NXDOMAIN
		dq:setRecords({})
	end

	return
end
