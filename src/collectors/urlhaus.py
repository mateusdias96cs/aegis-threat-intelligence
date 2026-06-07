"""URLhaus (abuse.ch) collector — recently submitted malicious URLs."""

import csv
import io
import requests
from datetime import date

ENDPOINT = "https://urlhaus.abuse.ch/downloads/csv_recent/"


def collect() -> list[dict]:
    """Collect recent malicious URLs from the URLhaus CSV feed.

    Returns:
        list[dict]: IOCs of type ``url``. Empty on fetch failure.
    """
    today = date.today().isoformat()

    try:
        response = requests.get(ENDPOINT, timeout=30)
        response.raise_for_status()
        content = response.text
    except Exception as e:
        print(f"[urlhaus] Error fetching feed: {e}")
        return []

    iocs = []
    try:
        reader = csv.reader(io.StringIO(content))
        for row in reader:
            if not row or row[0].startswith("#"):
                continue
            if len(row) < 9:
                continue

            _, dateadded, url, url_status, _, threat, tags, _, _ = row[:9]

            if not url:
                continue

            first_seen = dateadded.split(" ")[0] if dateadded else today

            if tags and tags.lower() not in ("", "null"):
                description = f"{threat} — {tags}"
            else:
                description = threat

            iocs.append({
                "type": "url",
                "value": url,
                "source": "URLhaus",
                "severity": "HIGH" if url_status == "online" else "MEDIUM",
                "description": description,
                "first_seen": first_seen,
                "last_seen": today,
                "country": None,
                "abuse_score": None,
                "mitre_technique_id": None,
                "mitre_tactic": None,
                "confidence_score": None,
            })

            if len(iocs) >= 2000:
                break

    except Exception as e:
        print(f"[urlhaus] Error parsing feed: {e}")
        return []

    return iocs
