import requests
from datetime import datetime

ENDPOINT = "https://threatfox.abuse.ch/export/json/recent/"

def collect() -> list[dict]:
    try:
        response = requests.get(ENDPOINT, timeout=30)
        response.raise_for_status()
        data = response.json()
        
        iocs = []
        for key, entry in data.items():
            if not isinstance(entry, list):
                # The data is usually under a top-level structure or directly a dict.
                # ThreatFox JSON recent export returns a dict where each key is an ID
                # and the value is a list of dicts.
                entry = [entry]
                
            for item in entry:
                # Map ThreatFox types to our internal types
                tf_type = item.get("ioc_type", "")
                internal_type = "unknown"
                if "ip" in tf_type:
                    internal_type = "ip"
                elif "domain" in tf_type:
                    internal_type = "domain"
                elif "url" in tf_type:
                    internal_type = "url"
                elif "hash" in tf_type or "md5" in tf_type or "sha" in tf_type:
                    internal_type = "hash"
                
                iocs.append({
                    "type": internal_type,
                    "value": item.get("ioc_value"),
                    "source": "ThreatFox",
                    "severity": "HIGH", # ThreatFox feeds are generally high confidence malware
                    "description": f"Malware: {item.get('malware_printable', 'Unknown')} - {item.get('threat_type', '')}",
                    "first_seen": datetime.utcnow().isoformat() + "Z"
                })
        
        return iocs
    except Exception as e:
        print(f"[threatfox] Error collecting data: {e}")
        return []
