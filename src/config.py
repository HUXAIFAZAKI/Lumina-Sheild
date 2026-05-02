import environs

env = environs.Env()
env.read_env()


def _read_api_keys(primary_name: str, *legacy_names: str) -> list[str]:
	keys = [key for key in env.list(primary_name, default=[]) if key]
	if keys:
		return keys

	for name in legacy_names:
		value = env.str(name, "").strip()
		if value:
			return [value]

	return []


LOG_LEVEL = env.str("LOG_LEVEL", "INFO")
VIRUSTOTAL_API_KEYS = _read_api_keys("VIRUSTOTAL_API_KEYS", "VT_API_KEY")
ALIENVAULT_OTX_API_KEYS = _read_api_keys(
	"ALIENVAULT_OTX_API_KEYS",
	"ALIENVAULT_OTX_API_KEY",
	"OTX_API_KEY",
)
ABUSEIPDB_API_KEYS = _read_api_keys("ABUSEIPDB_API_KEYS", "ABUSEIPDB_API_KEY")

ENABLE_VIRUSTOTAL = env.bool("ENABLE_VIRUSTOTAL", bool(VIRUSTOTAL_API_KEYS))
ENABLE_WHOIS = env.bool("ENABLE_WHOIS", True)
ENABLE_ABUSEIPDB = env.bool("ENABLE_ABUSEIPDB", bool(ABUSEIPDB_API_KEYS))
ENABLE_ALIENVAULT_OTX = env.bool("ENABLE_ALIENVAULT_OTX", bool(ALIENVAULT_OTX_API_KEYS))