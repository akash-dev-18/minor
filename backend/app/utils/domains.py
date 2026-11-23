from __future__ import annotations

import ipaddress
from functools import lru_cache

import tldextract

_extractor = tldextract.TLDExtract(suffix_list_urls=())


@lru_cache(maxsize=4096)
def registered_domain(host: str | None) -> str | None:
    if not host:
        return None
    host = host.strip().lower().rstrip(".")
    if not host:
        return None
    try:
        ipaddress.ip_address(host.strip("[]"))
        return host
    except ValueError:
        pass
    extracted = _extractor(host)
    if extracted.registered_domain:
        return extracted.registered_domain.lower()
    if extracted.domain and extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}".lower()
    return extracted.domain.lower() or None


def hostname_from_address(address: str | None) -> str | None:
    if not address:
        return None
    address = address.strip()
    if "@" not in address:
        return None
    domain = address.rsplit("@", 1)[1].strip().strip(">").lower()
    return domain or None


def is_ip_host(host: str | None) -> bool:
    if not host:
        return False
    candidate = host.strip("[]")
    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        return False


def levenshtein(left: str, right: str) -> int:
    if left == right:
        return 0
    if not left:
        return len(right)
    if not right:
        return len(left)
    previous = list(range(len(right) + 1))
    for i, left_char in enumerate(left, start=1):
        current = [i]
        for j, right_char in enumerate(right, start=1):
            insert = current[j - 1] + 1
            delete = previous[j] + 1
            substitute = previous[j - 1] + (left_char != right_char)
            current.append(min(insert, delete, substitute))
        previous = current
    return previous[-1]


def lookalike_brand(domain: str, brands: dict[str, str]) -> str | None:
    """Return the impersonated brand name when the domain resembles it."""
    if not domain:
        return None
    label = domain.split(".")[0]
    if label in brands.values():
        return None
    for brand_name, brand_label in brands.items():
        if label == brand_label:
            return None
        if levenshtein(label, brand_label) <= 1 and len(brand_label) >= 4:
            return brand_name
        if brand_label in label and label != brand_label and len(label) <= len(brand_label) + 6:
            return brand_name
    return None
