"""IOC normalizer — enforces a uniform schema across all collectors."""

REQUIRED_KEYS = [
    "type", "value", "source", "severity",
    "country", "abuse_score", "description",
    "first_seen", "last_seen",
]

LOWERCASE_TYPES = {"ip", "domain", "url"}


def normalize(iocs: list) -> list:
    """Normalize raw collector IOCs into a uniform shape.

    Ensures the required keys exist (``REQUIRED_KEYS``, with ``None`` as
    fallback), strips strings and lowercases ``value`` for ``ip``/``domain``/
    ``url`` types. Drops entries without a ``value`` and preserves every other
    field produced by the collectors.

    Args:
        iocs: List of IOC dicts from the collectors.

    Returns:
        list: Normalized IOCs.
    """
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
