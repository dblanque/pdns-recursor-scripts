import dns.resolver
from enum import Enum
import sys

class bcolors(Enum):
	def __str__(self):
		return str(self.value)

	# Colors
	RED = "\033[1;31m"
	GREEN = "\033[1;32m"
	YELLOW = "\033[1;33m"
	BLUE = "\033[1;34m"
	MAGENTA = "\033[1;35m"
	CYAN = "\033[1;36m"
	L_RED = "\033[91m"
	L_GREEN = "\033[92m"
	L_YELLOW = "\033[93m"
	L_BLUE = "\033[94m"
	L_MAGENTA = "\033[95m"
	L_CYAN = "\033[96m"

	# Formatting
	NC = "\033[0m"  # No Color
	BOLD = "\033[1m"
	UNDERLINE = "\033[4m"
	BLINK = "\033[5m"

def print_c(color: bcolors, message: str, **kwargs):
	"""
	Concatenates and prints {color}{message}{nc}
	"""
	force_print = kwargs.pop("force_print", False)
	if "pytest" not in sys.modules and not force_print:
		return print(f"{color}{message}{bcolors.NC}", **kwargs)

def colorize(color: bcolors, message: str):
	return f"{color}{message}{bcolors.NC}"

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
	# Domain, Type, Should resolve
	("google.com",					"A", True),
	("example.com",					"A", False),
	("whitelisted.example.com",		"A", True),
	("example.org",					"A", True),
	("sub.example.org",				"A", False),
	("yahoo.com",					"A", False),
	("sub.yahoo.com",				"A", False),
	("bing.com",					"A", False),
	("sub.bing.com",				"A", False),
	("microsoft.com",				"A", False),
	("sub.microsoft.com",			"A", False),
	("mozilla.org",					"A", False),
	("youtube.com",					"A", False),
	("yandex.ru",					"A", False),
	("regex101.com",				"A", False),

	# Blocked but whitelisted
	("google-analytics.com",		"A", True),
	("srienlinea.sri.gob.ec",		"A", True),
	("pichincha.com",				"A", True),
):
	domain, q_type, expects_resolve = q_case
	lookup = dns_lookup(domain, q_type, DNS_IP)
	sinkholed = assert_ip(lookup, "0.0.0.0")
	if sinkholed is expects_resolve:
		print(
			"Test %s for %s (%s)" % (
				colorize(bcolors.L_RED, "FAILED"),
				domain,
				str(lookup)
			)
		)
	else:
		print(
			"Test %s for %s (%s)" % (
				colorize(bcolors.L_GREEN, "PASSED"),
				domain,
				str(lookup)
			)
		)

for q_case in (
	("localhost", "A", "127.0.0.1",),
):
	domain, q_type, expected = q_case
	lookup = dns_lookup(domain, q_type, DNS_IP)
	if not assert_ip(lookup, expected):
		print(
			"Test %s for %s (%s)" % (
				colorize(bcolors.L_RED, "FAILED"),
				domain,
				str(lookup)
			)
		)
	else:
		print(
			"Test %s for %s (%s)" % (
				colorize(bcolors.L_GREEN, "PASSED"),
				domain,
				str(lookup)
			)
		)
