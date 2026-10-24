import re
import sys
import ipaddress
from difflib import SequenceMatcher
from urllib.parse import urlparse

import tldextract

# official domains
BRAND_DOMAINS = {
    "paypal": "paypal.com",
    "google": "google.com",
    "apple": "apple.com",
    "amazon": "amazon.com",
    "microsoft": "microsoft.com",
    "netflix": "netflix.com",
    "facebook": "facebook.com",
}
#safe domains
SAFE_DOMAINS = {
    "amazonaws.com", "googleapis.com", "googleusercontent.com",
    "microsoftonline.com", "microsoft.com", "live.com", "office.com",
    "icloud.com", "applebees.com", "pineapple.com",
}

# country versions of a brand's real site (amazon.co.uk, google.de)
REGIONAL_SUFFIXES = {"com", "co.uk", "de", "fr", "ca", "com.au", "co.jp",
                     "it", "es", "nl", "in", "co.in", "com.br", "com.mx"}


SUSPICIOUS_WORDS = {"login", "secure", "verify", "account", "update", "signin", "bank"}

# common character swaps
SWAPS = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "$": "s"})


_extract = tldextract.TLDExtract(suffix_list_urls=())

def normalize(label: str) -> str:
    """Undo common lookalike tricks so 'paypa1' becomes 'paypal'."""
    label = label.lower().translate(SWAPS)
    return label.replace("rn", "m").replace("vv", "w")


def is_ip_address(host: str) -> bool:
    """True for normal IPs and for IPs disguised as one big number or hex."""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(re.fullmatch(r"\d+|0x[0-9a-fA-F]+", host))


# main

def analyze_url(url: str) -> dict:
    """Analyze one URL. Returns {"url", "domain", "score", "reasons"}."""
    url = url.strip()

    # urlparse only finds the domain if the URL has a scheme
    had_scheme = "://" in url
    if not had_scheme:
        url = "http://" + url

    try:
        parsed = urlparse(url)
        domain = parsed.hostname
    except ValueError:
        return {"url": url, "domain": None, "score": 100,
                "reasons": ["Malformed URL"]}

    if not domain:
        return {"url": url, "domain": None, "score": 100,
                "reasons": ["Could not extract a valid domain"]}

    score = 0
    sub_score = 0          # score cap for subdomains
    reasons = []
    is_ip = is_ip_address(domain)

    # Checks ip
    if is_ip:
        score += 40
        reasons.append("Link uses an IP address instead of a domain name")

    # Checks long urls
    if len(url) > 100:
        score += 20
        reasons.append(f"URL is very long ({len(url)} characters)")
    elif len(url) > 75:
        score += 10
        reasons.append(f"URL is unusually long ({len(url)} characters)")

    # Checks no https
    if had_scheme and parsed.scheme == "http":
        score += 5
        reasons.append("Link does not use HTTPS")

    # Checks for @ in netloc
    if "@" in parsed.netloc:
        score += 30
        fake_part = parsed.username or ""
        reasons.append(
            f"URL contains '@', the text ('{fake_part}') is ignored by "
            f"browsers; the real destination is {domain}"
        )
        if "." in fake_part:
            score += 10
            reasons.append("Text before '@' is formatted like a domain name (decoy)")

    # Domain name check
    if not is_ip:
        ext = _extract(domain)
        main_domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
        subdomains = [s for s in ext.subdomain.split(".") if s and s != "www"]

        # Check: unrecognized top-level domain
        if not ext.suffix:
            score += 15
            reasons.append("Domain has no recognized top-level domain")

        # Check: too many subdomains
        if len(subdomains) >= 4:
            sub_score += 10
            reasons.append(f"Excessive subdomains ({len(subdomains)}): {'.'.join(subdomains)}")
        elif len(subdomains) == 3:
            sub_score += 5
            reasons.append(f"Many subdomains ({len(subdomains)}): {'.'.join(subdomains)}")

        # Check: brand name hiding in the subdomain
        for brand in BRAND_DOMAINS:
            if any(brand in part for part in subdomains) and brand not in main_domain:
                sub_score += 30
                reasons.append(
                    f"Brand '{brand}' appears in the subdomain but the real domain is {main_domain}"
                )
                break

        # Check: suspicious keywords in the subdomain
        found = sorted(w for w in SUSPICIOUS_WORDS if any(w in part for part in subdomains))
        if found:
            sub_score += 10
            reasons.append(f"Suspicious keywords in subdomain: {', '.join(found)}")

        score += min(sub_score, 40)

        # Check: lookalike domains
        label = ext.domain.lower()
        norm = normalize(label)

        if "xn--" in domain:
            score += 25
            reasons.append("Domain uses punycode (xn--), which can disguise lookalike characters")

        if main_domain not in SAFE_DOMAINS:
            for brand, official in BRAND_DOMAINS.items():
                if main_domain == official or (label == brand and ext.suffix in REGIONAL_SUFFIXES):
                    break
                if norm == brand and label != brand:
                    score += 30
                    reasons.append(f"'{main_domain}' imitates {official} using look-alike characters")
                    break
                if label == brand:
                    score += 25
                    reasons.append(f"Uses the name '{brand}' but is not the official site ({official})")
                    break
                if brand in label:
                    score += 25
                    reasons.append(f"'{main_domain}' contains '{brand}' but is not {official}")
                    break
                if SequenceMatcher(None, norm, brand).ratio() >= 0.85:
                    score += 25
                    reasons.append(f"'{main_domain}' is very similar to {official}")
                    break

    return {"url": url, "domain": domain, "score": min(score, 100), "reasons": reasons}