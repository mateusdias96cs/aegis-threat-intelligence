"""IOC deduplicator — collapses duplicates by value, keeping highest severity."""

SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def _severity_rank(ioc: dict) -> int:
    severity = ioc.get("severity") or ""
    try:
        return SEVERITY_ORDER.index(severity.upper())
    except ValueError:
        return -1


def deduplicate(iocs: list) -> list:
    """Remove duplicate IOCs by ``value``, keeping the highest severity.

    For each repeated ``value``, keeps the occurrence with the highest
    severity (order LOW < MEDIUM < HIGH < CRITICAL). Entries without a
    ``value`` are dropped.

    Args:
        iocs: List of normalized IOCs.

    Returns:
        list: Unique IOCs.
    """
    seen: dict[str, dict] = {}

    for ioc in iocs:
        value = ioc.get("value")
        # Skip entries with no value to avoid None as dict key
        if value is None:
            continue
        if value not in seen or _severity_rank(ioc) > _severity_rank(seen[value]):
            seen[value] = ioc

    return list(seen.values())
