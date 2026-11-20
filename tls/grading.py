"""A–F grade for a host, derived from its findings."""


def grade(findings):
    """Score findings into a letter grade (A best, F worst)."""
    score = 100
    for f in findings:
        if f["severity"] == "CRITICAL":
            score -= 40
        elif f["severity"] == "HIGH":
            score -= 20
        elif f["severity"] == "MEDIUM":
            score -= 10
        else:
            score -= 5
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def grade_host(host, findings):
    """Return (host, grade) for one host's findings."""
    mine = [f for f in findings if f["object"] == host.get("host", "?")]
    return host.get("host", "?"), grade(mine)
