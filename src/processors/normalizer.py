REQUIRED_KEYS = [
    "type", "value", "source", "severity",
    "country", "abuse_score", "description",
    "first_seen", "last_seen",
]

LOWERCASE_TYPES = {"ip", "domain", "url"}


def normalize(iocs: list) -> list:
    cleaned = []
    for ioc in iocs:
        entry = {key: ioc.get(key) for key in REQUIRED_KEYS}

        for key in list(entry):
            val = entry[key]
            if isinstance(val, str):
                entry[key] = val.strip()

        value = entry.get("value")
        if not value:
            continue

        if entry.get("type") in LOWERCASE_TYPES and isinstance(value, str):
            entry["value"] = value.lower()

        cleaned.append(entry)
    return cleaned
