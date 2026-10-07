import re
from urllib.parse import urlparse


def scan_url(url):

    url = url.strip()

    if not url:
        return {
            "status": "error",
            "message": "URL is empty."
        }

    if not re.match(
        r"^https?://",
        url,
        re.IGNORECASE
    ):
        url = "https://" + url

    try:

        parsed = urlparse(url)

        if not parsed.netloc:

            return {
                "status": "error",
                "message": "Invalid URL."
            }

        hostname = parsed.hostname

        if not hostname:

            return {
                "status": "error",
                "message": "Unable to read domain."
            }

        warnings = []

        # HTTPS check
        if parsed.scheme.lower() != "https":
            warnings.append(
                "The URL does not use HTTPS."
            )

        # IP address check
        if re.match(
            r"^\d{1,3}(\.\d{1,3}){3}$",
            hostname
        ):
            warnings.append(
                "The URL uses an IP address instead of a domain name."
            )

        # Suspicious URL patterns
        suspicious_words = [
            "login",
            "verify",
            "account",
            "password",
            "secure",
            "update",
            "confirm",
            "wallet",
            "payment"
        ]

        lower_url = url.lower()

        found_words = []

        for word in suspicious_words:

            if word in lower_url:
                found_words.append(word)

        if found_words:

            warnings.append(
                "Security-related keywords detected: "
                + ", ".join(found_words)
            )

        # Very long URL
        if len(url) > 200:

            warnings.append(
                "The URL is unusually long."
            )

        # @ symbol
        if "@" in url:

            warnings.append(
                "The URL contains an @ symbol."
            )

        # Too many subdomains
        parts = hostname.split(".")

        if len(parts) > 4:

            warnings.append(
                "The domain contains many subdomains."
            )

        if warnings:

            status = "suspicious"

            message = (
                "Potentially suspicious indicators "
                "were detected. Review the URL carefully."
            )

        else:

            status = "low-risk"

            message = (
                "No basic suspicious indicators "
                "were detected."
            )

        return {

            "status":
                status,

            "url":
                url,

            "domain":
                hostname,

            "protocol":
                parsed.scheme,

            "warnings":
                warnings,

            "message":
                message

        }

    except Exception as e:

        return {

            "status":
                "error",

            "message":
                "Unable to analyze the URL."

        }