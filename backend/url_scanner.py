"""Offline URL risk heuristics. This module never fetches the submitted URL."""

import ipaddress
import re
from urllib.parse import unquote, urlsplit


MAX_URL_LENGTH = 4096
SHORTENER_DOMAINS = {
    "bit.ly", "cutt.ly", "is.gd", "ow.ly", "rb.gy", "shorturl.at",
    "t.co", "tiny.cc", "tinyurl.com",
}
HIGH_RISK_TLDS = {"click", "country", "gq", "icu", "kim", "link", "loan", "men", "mom", "party", "rest", "top", "work", "zip"}
BRANDS = {
    "amazon", "apple", "facebook", "google", "instagram", "microsoft",
    "netflix", "paypal", "spotify", "whatsapp",
}


def _risk_level(score):
    if score >= 80:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 30:
        return "Medium"
    return "Low"


def scan_url(value):
    """Return a stable risk score and explainable indicators for a URL string."""
    raw = str(value or "").strip()
    if not raw:
        return {"status": "error", "message": "URL is empty.", "risk_score": 0, "warnings": []}
    if len(raw) > MAX_URL_LENGTH:
        return {"status": "error", "message": "URL exceeds the 4096 character limit.", "risk_score": 0, "warnings": []}
    if any(ord(char) < 32 or ord(char) == 127 for char in raw):
        return {"status": "error", "message": "URL contains control characters.", "risk_score": 0, "warnings": []}

    candidate = raw if re.match(r"^[a-z][a-z0-9+.-]*://", raw, re.I) else "https://" + raw
    try:
        parsed = urlsplit(candidate)
        hostname = parsed.hostname
        # Accessing .port validates malformed or out-of-range ports.
        port = parsed.port
    except ValueError:
        return {"status": "error", "message": "Enter a valid HTTP or HTTPS URL.", "risk_score": 0, "warnings": []}
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc or not hostname:
        return {"status": "error", "message": "Enter a valid HTTP or HTTPS URL.", "risk_score": 0, "warnings": []}

    warnings = []
    score = 0

    def flag(points, message):
        nonlocal score
        score += points
        warnings.append(message)

    if parsed.scheme.lower() == "http":
        flag(15, "The URL does not use HTTPS.")
    if parsed.username is not None or parsed.password is not None:
        flag(35, "The URL embeds user information before the hostname.")

    host = hostname.rstrip(".").lower()
    try:
        address = ipaddress.ip_address(host)
        if not address.is_global:
            flag(30, "The URL points to a non-public IP address.")
        else:
            flag(20, "The URL uses a raw IP address instead of a domain name.")
    except ValueError:
        labels = host.split(".")
        if len(labels) < 2 or any(not label for label in labels):
            return {"status": "error", "message": "Enter a valid hostname.", "risk_score": 0, "warnings": []}
        try:
            ascii_host = host.encode("idna").decode("ascii")
        except UnicodeError:
            ascii_host = host
        if "xn--" in ascii_host:
            flag(25, "The hostname uses internationalized (punycode) characters.")
        if len(labels) > 4:
            flag(10, "The domain contains many subdomains.")
        if labels[-1] in HIGH_RISK_TLDS:
            flag(15, "The domain uses a top-level domain commonly seen in abuse.")
        registrable = labels[-2] if len(labels) >= 2 else labels[0]
        for brand in BRANDS:
            if brand in registrable and registrable != brand:
                flag(25, f"The hostname contains a brand name in an unexpected domain label ({brand}).")
                break
        if host in SHORTENER_DOMAINS:
            flag(15, "The URL uses a link-shortening service that hides its destination.")

    decoded = unquote(candidate)
    lowered = decoded.lower()
    if len(candidate) > 200:
        flag(10, "The URL is unusually long.")
    if "\\" in candidate:
        flag(15, "The URL contains backslashes that can make its destination ambiguous.")
    if "%00" in candidate.lower() or re.search(r"%0[ad]", candidate, re.I):
        flag(10, "The URL contains encoded control characters.")
    if port and port not in {80, 443}:
        flag(5, "The URL specifies a non-standard port.")

    suspicious_words = ("account", "billing", "confirm", "credential", "password", "payment", "recover", "signin", "verify", "wallet")
    found_words = [word for word in suspicious_words if re.search(rf"(?<![a-z]){word}(?![a-z])", lowered)]
    if found_words:
        flag(min(20, 5 * len(found_words)), "Security-related words appear in the URL: " + ", ".join(found_words) + ".")

    score = min(100, score)
    status = "suspicious" if score >= 30 else "low-risk"
    return {
        "status": status,
        "url": candidate,
        "domain": host,
        "protocol": parsed.scheme.lower(),
        "risk_score": score,
        "risk_level": _risk_level(score),
        "warnings": warnings,
        "message": "Potentially suspicious indicators were detected. Review the destination carefully." if warnings else "No basic suspicious indicators were detected.",
    }
