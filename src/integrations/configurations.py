from src.integrations.engines.virustotal import VirusTotalIntegration
from src.integrations.engines.whois import WhoisIntegration
from src.integrations.engines.alienvault_otx import AlienVaultOTXIntegration
from src.integrations.engines.abuseip_db import AbuseIPDBIntegration
from src import config

INTEGRATIONS: list[dict[str, any]] = [
    {
        "name":             "virustotal",
        "enabled":          config.ENABLE_VIRUSTOTAL,
        "allowed_types":   ["hash", "ip", "domain", "url"],
        "classname":        "VirusTotalIntegration",
        "class_ref":        VirusTotalIntegration,
        "base_url":         "https://www.virustotal.com/api/v3",
        "apis":             config.VIRUSTOTAL_API_KEYS,
        "timeout":          10,
        "retry_count":      2,
        "rate_limit_delay": 1,
    },
    {
        "name":             "whois",
        "enabled":          config.ENABLE_WHOIS,
        "allowed_types":   ["ip", "domain", "url"],
        "classname":        "WhoisIntegration",
        "class_ref":        WhoisIntegration,
        "base_url":         "",
        "apis":             [],
        "timeout":          10,
        "retry_count":      1,
        "rate_limit_delay": 2,
    },
    {
        "name":             "alienvaultotx",
        "enabled":          config.ENABLE_ALIENVAULT_OTX,
        "allowed_types":   ["hash", "domain", "ip", "url"],
        "classname":        "AlienVaultOTXIntegration",
        "class_ref":        AlienVaultOTXIntegration,
        "base_url":         "https://otx.alienvault.com",
        "apis":             config.ALIENVAULT_OTX_API_KEYS,
        "timeout":          10,
        "retry_count":      1,
        "rate_limit_delay": 2,
    },
    {
        "name":             "abuseipdb",
        "enabled":          config.ENABLE_ABUSEIPDB,
        "allowed_types":   ["ip", "url"],
        "classname":        "AbuseIPDBIntegration",
        "class_ref":        AbuseIPDBIntegration,
        "base_url":         "https://api.abuseipdb.com",
        "apis":             config.ABUSEIPDB_API_KEYS,
        "timeout":          10,
        "retry_count":      1,
        "rate_limit_delay": 2,
    },
]
 
INTEGRATION_REGISTRY: dict[str, type] = {
    integration["classname"]: integration["class_ref"]
    for integration in INTEGRATIONS
}