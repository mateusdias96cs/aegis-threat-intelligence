REQUIRED_KEYS = [
    "type", "value", "source", "severity",
    "country", "abuse_score", "description",
    "first_seen", "last_seen",
]

LOWERCASE_TYPES = {"ip", "domain", "url"}


def normalize(iocs: list) -> list:
    cleaned = []
    for ioc in iocs:
        # Preserva todos os campos do collector — não descartar nada
        entry = dict(ioc)

        # Garante que required keys existem (None como fallback)
        for key in REQUIRED_KEYS:
            if key not in entry:
                entry[key] = None

        # Strip de strings
        for key in list(entry):
            val = entry[key]
            if isinstance(val, str):
                entry[key] = val.strip()

        # value obrigatório
        if not entry.get("value"):
            continue

        # Lowercase para tipos específicos
        if entry.get("type") in LOWERCASE_TYPES and isinstance(entry["value"], str):
            entry["value"] = entry["value"].lower()

        cleaned.append(entry)
    return cleaned
