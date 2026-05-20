import requests
from datetime import date, datetime, timedelta, timezone

FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def collect() -> list[dict]:
    try:
        response = requests.get(FEED_URL, timeout=30)
        response.raise_for_status()
        vulnerabilities = response.json().get("vulnerabilities", [])
    except requests.RequestException as e:
        print(f"[cisa] failed to fetch KEV feed: {e}")
        return []

    today = date.today().isoformat()
    cutoff = datetime.now(timezone.utc) - timedelta(days=90)
    all_vulns = vulnerabilities
    vulnerabilities = [
        v for v in all_vulns
        if datetime.strptime(v.get("dateAdded", "1970-01-01"), "%Y-%m-%d").replace(tzinfo=timezone.utc) >= cutoff
    ]
    print(f"[cisa] {len(vulnerabilities)} recent CVEs (last 90 days) of {len(all_vulns)} total")

    iocs = []

    for vuln in vulnerabilities:
        cve_id = vuln.get("cveID")
        if not cve_id:
            continue

        vendor = vuln.get("vendorProject") or ""
        vuln_name = vuln.get("vulnerabilityName") or ""
        description = f"{vendor} - {vuln_name}".strip(" -") or vuln_name or vendor

        ransomware_use = vuln.get("knownRansomwareCampaignUse", "")
        iocs.append({
            "type": "cve",
            "value": cve_id,
            "source": "CISA-KEV",
            "description": description,
            "first_seen": vuln.get("dateAdded"),
            "last_seen": today,
            "severity": "CRITICAL" if ransomware_use == "Known" else "HIGH",
            "country": None,
            "abuse_score": None,
        })

    return iocs
