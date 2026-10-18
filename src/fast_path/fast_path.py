# Role: Module 1 - entry triage (Fast-Path)
# Description: Immediate rejection or allowance (whitelist/blacklist filtering)

"""Moduł 1: fast_path – triage biała/czarna lista (architecture/modules/fast_path.md)."""

from functools import lru_cache

from domain_analyzer import (
    TRUSTED_DOMAINS,
    load_phishtank_hosts,
    load_tranco,
    normalize_host,
    registrable_domain,
)

AMOUNT_TOLERANCE = 1.5
# PhishTank zawiera hosty współdzielone (sites.google.com, drive.google.com, bit.ly, goo.gl).
# Domeny z czołówki Tranco nie trafiają na czarną listę, żeby nie blokować całego Google.
BLACKLIST_TRANCO_EXCLUDE_TOP = 10_000


@lru_cache(maxsize=None)
def build_blacklist() -> frozenset[str]:
    popular = load_tranco(BLACKLIST_TRANCO_EXCLUDE_TOP)
    return frozenset(h for h in load_phishtank_hosts() if registrable_domain(h) not in popular)


def _parent_domains(host: str):
    """'a.b.evil.com' -> 'a.b.evil.com', 'b.evil.com', 'evil.com' (do domeny rejestrowalnej włącznie)."""
    reg = registrable_domain(host)
    labels = host.split(".")
    for i in range(len(labels)):
        candidate = ".".join(labels[i:])
        yield candidate
        if candidate == reg:
            break


def _result(verdict: str, reason_code: str, bypass: bool) -> dict:
    return {"verdict": verdict, "reason_code": reason_code, "bypass_pipeline": bypass}


def check(payload: dict, trusted=TRUSTED_DOMAINS, blacklist=None) -> dict:
    """payload: {"domain": str, "amount": float, "history_avg_amount": float}"""
    host = normalize_host(payload["domain"])
    parents = list(_parent_domains(host))

    if any(p in trusted for p in parents):
        if payload["amount"] <= AMOUNT_TOLERANCE * payload["history_avg_amount"]:
            return _result("ALLOW", "KNOWN_BENIGN", True)
        return _result("DEEP_CHECK", "UNUSUAL_AMOUNT", False)

    if blacklist is None:
        blacklist = build_blacklist()
    if any(p in blacklist for p in parents):
        return _result("BLOCK", "BLACKLISTED_PHISH", True)

    return _result("DEEP_CHECK", "UNKNOWN_DOMAIN", False)
