SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


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
