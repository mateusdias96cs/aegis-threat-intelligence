SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

_SOURCE_SCORES = {
    "CISA-KEV":       20,
    "ThreatFox":      15,
    "AlienVault-OTX": 10,
}


def calculate_confidence(ioc: dict, all_iocs: list) -> int:
    score = 0

    # Source count across the batch
    value = ioc.get("value", "")
    source_count = sum(1 for i in all_iocs if i.get("value") == value)
    if source_count >= 3:
        score += 40
    elif source_count == 2:
        score += 25
    else:
        score += 10

    # AbuseIPDB confidence
    abuse = ioc.get("abuse_score")
    if abuse is not None:
        if abuse >= 90:
            score += 30
        elif abuse >= 70:
            score += 20
        elif abuse >= 40:
            score += 10
        elif abuse > 0:
            score += 5

    # Severity
    severity = (ioc.get("severity") or "").upper()
    if severity == "CRITICAL":
        score += 20
    elif severity == "HIGH":
        score += 10
    elif severity == "MEDIUM":
        score += 5

    # Source reliability
    score += _SOURCE_SCORES.get(ioc.get("source", ""), 0)

    return min(score, 100)


def apply_confidence(iocs: list) -> list:
    for ioc in iocs:
        ioc["confidence_score"] = calculate_confidence(ioc, iocs)
    return iocs


def classify(iocs: list) -> list:
    for ioc in iocs:
        score = ioc.get("abuse_score")

        if score is not None:
            if score >= 90:
                ioc["severity"] = "CRITICAL"
            elif score >= 70:
                ioc["severity"] = "HIGH"
            elif score >= 40:
                ioc["severity"] = "MEDIUM"
            elif score > 0:
                ioc["severity"] = "LOW"
            else:
                ioc["severity"] = ioc.get("severity") or "MEDIUM"
        elif ioc.get("source") == "CISA-KEV":
            pass
        else:
            ioc["severity"] = ioc.get("severity") or "MEDIUM"

    return iocs
