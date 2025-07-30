import dns.resolver

def dns_lookup(domain, record_type=None, dns_server=None, verbose=False) -> list[str]:
	results: list[str] = []
	if not dns_server:
		raise ValueError("dns_server is a required value")
	if not record_type:
		raise ValueError("record_type is a required value")
	resolver = dns.resolver.Resolver()
	resolver.nameservers = [dns_server]  # Set the DNS server

	try:
		answers = resolver.resolve(domain, record_type)
		for rdata in answers:
			rdata_text = rdata.to_text()
			if verbose:
				print(f"{record_type} record for {domain}: {rdata_text}")
			if rdata_text not in results:
				results.append(rdata.to_text())
	except dns.resolver.NXDOMAIN:
		if verbose:
			print(f"The domain {domain} does not exist")
	except dns.resolver.NoAnswer:
		if verbose:
			print(f"No {record_type} records found for {domain}")
	except dns.resolver.Timeout:
		if verbose:
			print("DNS query timed out")
	except Exception as e:
		if verbose:
			print(f"DNS query failed: {e}")
	return results

def assert_ip(qnames, ip):
	if ip not in qnames:
		return False
	return True

DNS_IP = "10.10.10.101"
for q_case in (
	# Domain, Type, Should be sinkholed
	("google.com", "A", True),
	("000free.us", "A", False),
	("ad-assets.futurecdn.net", "A", False),
):
	domain, q_type, sinkhole = q_case
	sinkholed = assert_ip(dns_lookup(domain, q_type, DNS_IP), "0.0.0.0")
	msg = "was resolved"
	if sinkholed:
		msg = "was sinkholed"
	print(f"{domain} {msg}.")

for q_case in (
	("localhost", "A", "127.0.0.1",),
):
	domain, q_type, expected = q_case
	lookup = dns_lookup(domain, q_type, DNS_IP)
	if not assert_ip(lookup, expected):
		print(f"Bad lookup for {domain} ({str(lookup)})")
