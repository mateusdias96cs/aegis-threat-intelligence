"""CISA KEV collector — actively exploited CVEs (Known Exploited Vulnerabilities)."""

import time

import requests
from datetime import date, datetime, timedelta, timezone

FEED_URL    = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_NVD_API    = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_NVD_SLEEP  = 0.7   # 5 req/30 s → ~6 req/30 s max; 0.7 s gives safe headroom
_NVD_TIMEOUT = 5


def _fetch_cvss(cve_id: str) -> float | None:
    """Fetches CVSS base score from NVD for a single CVE.
    Priority: v3.1 > v3.0 > v2.0. Returns None on any failure."""
    try:
        resp = requests.get(_NVD_API, params={"cveId": cve_id}, timeout=_NVD_TIMEOUT)
        resp.raise_for_status()
        items = resp.json().get("vulnerabilities", [])
        if not items:
            return None
        metrics = items[0].get("cve", {}).get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key, [])
            if entries:
                score = entries[0].get("cvssData", {}).get("baseScore")
                if score is not None:
                    return float(score)
        return None
    except Exception:
        return None


def collect() -> list[dict]:
    """Collect actively exploited CVEs from the CISA KEV feed.

    Fetches the Known Exploited Vulnerabilities JSON feed, keeps recently
    added entries and enriches each one with its CVSS base score from the
    NVD API.

    Returns:
        list[dict]: IOCs of type ``cve``. Empty on fetch failure.
    """
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
            "cvss_score": None,
        })

    # ── NVD CVSS enrichment ───────────────────────────────────────────────────
    print(f"[cisa] fetching CVSS from NVD for {len(iocs)} CVEs…")
    found = not_found = 0
    for ioc in iocs:
        score = _fetch_cvss(ioc["value"])
        ioc["cvss_score"] = score
        if score is not None:
            found += 1
        else:
            not_found += 1
        time.sleep(_NVD_SLEEP)
    print(f"[cisa] NVD CVSS: {found} found, {not_found} not found")

    return iocs
