SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def _severity_rank(ioc: dict) -> int:
    severity = ioc.get("severity") or ""
    try:
        return SEVERITY_ORDER.index(severity.upper())
    except ValueError:
        return -1


def deduplicate(iocs: list) -> list:
    seen: dict[str, dict] = {}

    for ioc in iocs:
        value = ioc.get("value")
        # Skip entries with no value to avoid None as dict key
        if value is None:
            continue
        if value not in seen or _severity_rank(ioc) > _severity_rank(seen[value]):
            seen[value] = ioc

    return list(seen.values())
