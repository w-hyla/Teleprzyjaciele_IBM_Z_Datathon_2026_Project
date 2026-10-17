"""Moduł 2: domain_analyzer – homoglify, typosquatting, DGA (architecture/modules/domain_analyzer.md)."""

import math
import unicodedata
from collections import Counter

from src.domain_utils import (
    TRUSTED_DOMAINS,
    load_homoglyph_map,
    load_tranco,
    normalize_host,
    registrable_domain,
    split_host,
)

HOMOGLYPH_RISK = 0.95
# Odległość Levenshteina -> ryzyko. d=0 występuje tylko w subdomenie (np. 'mbank.pl.evil.top').
TYPO_RISK_BY_DIST = {0: 0.90, 1: 0.90, 2: 0.70}
DGA_RISK = 0.75
BASELINE_RISK = 0.05

ENTROPY_THRESHOLD = 3.8
CONSONANT_VOWEL_THRESHOLD = 4.0
MIN_LETTERS_FOR_RATIO = 8
VOWELS = frozenset("aeiouy")
MULTI_CHAR_CONFUSABLES = (("rn", "m"), ("cl", "d"))
# Domeny z czołówki Tranco to ugruntowane serwisy – ich SLD nie oznaczamy jako typosquatting.
TYPO_SKIP_TRANCO_TOP = 100_000


def levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def _decode_label(label: str) -> str:
    if label.startswith("xn--"):
        try:
            return label.encode("ascii").decode("idna")
        except UnicodeError:
            pass
        # Kodek idna odrzuca etykiety, które nie wracają do tej samej postaci – surowy punycode i tak je odczyta.
        try:
            return label[4:].encode("ascii").decode("punycode")
        except UnicodeError:
            return label
    return label


def _scripts(label: str) -> set[str]:
    """Alfabety liter w etykiecie, np. {'LATIN', 'CYRILLIC'}."""
    return {unicodedata.name(c, "?").split(" ")[0] for c in label if c.isalpha()}


def _skeleton(label: str) -> str:
    hmap = load_homoglyph_map()
    s = "".join(hmap.get(c, c) for c in label)
    for seq, replacement in MULTI_CHAR_CONFUSABLES:
        s = s.replace(seq, replacement)
    return s


def _max_typo_dist(brand_sld: str, whole_sld: bool) -> int:
    """Krótkie nazwy (np. 'ing') przy d<=2 pasowałyby do połowy internetu.

    Fragmenty (etykiety subdomeny, części SLD rozdzielone myślnikiem) to często zwykłe słowa
    ('bank' jest o 1 literę od 'mbank'), więc dla nich krótkie marki muszą pasować dokładnie.
    """
    if len(brand_sld) < 4 or (not whole_sld and len(brand_sld) < 7):
        return 0
    return 1 if len(brand_sld) < 7 else 2


def _typo_candidates(sub_labels: list[str], sld: str) -> list[tuple[str, bool, bool]]:
    """Krotki (tekst, czy_cały_SLD, czy_pochodzi_z_SLD).

    'mbank-login.evil.com' -> ('evil', True, True), ('mbank-login', False, False), ('mbank', False, False), ...
    """
    candidates = [(sld, True, True)]
    for label in sub_labels:
        candidates.append((label, False, False))
    for label, from_sld in [*((s, False) for s in sub_labels), (sld, True)]:
        tokens = [t for t in label.split("-") if t]
        if len(tokens) > 1:
            candidates.extend((t, False, from_sld) for t in tokens)
    return candidates


def analyze(domain: str, target_brands=None) -> dict:
    brands = TRUSTED_DOMAINS if target_brands is None else target_brands
    brand_slds = {split_host(b)[1]: b for b in brands}

    host = normalize_host(domain)
    registrable = registrable_domain(host)
    sub_labels, sld, _ = split_host(host)
    sub_labels = [_decode_label(label) for label in sub_labels]
    sld = _decode_label(sld)
    is_official = registrable in brands

    risk = 0.0
    reasons = []

    # 1. Homoglify / Punycode (UTS #39). Domena z nie-ASCII to IDN, który w DNS i tak idzie jako xn--.
    is_punycode = "xn--" in host or not host.isascii()
    has_mixed_scripts = any(len(_scripts(label)) > 1 for label in [*sub_labels, sld])
    skeleton_hit = None
    for label in [sld, *sub_labels]:
        sk = _skeleton(label)
        if sk != label and sk in brand_slds:
            skeleton_hit = brand_slds[sk]
            break
    if not is_official and (is_punycode or has_mixed_scripts or skeleton_hit):
        risk = max(risk, HOMOGLYPH_RISK)
        reasons.append("HOMOGLYPH_DETECTED")

    # 2. Typosquatting (Levenshtein) – SLD, etykiety subdomeny i ich części rozdzielone myślnikiem.
    min_dist = 0 if is_official else None
    closest_brand = registrable if is_official else skeleton_hit
    typo_risk = 0.0
    if not is_official:
        sld_is_popular = registrable in load_tranco(TYPO_SKIP_TRANCO_TOP)
        for text, whole_sld, from_sld in _typo_candidates(sub_labels, sld):
            for brand_sld, brand in brand_slds.items():
                d = levenshtein(text, brand_sld)
                if min_dist is None or d < min_dist:
                    min_dist = d
                if from_sld and sld_is_popular:
                    continue
                if d == 0 and whole_sld:
                    continue  # ten sam SLD, inny sufiks (np. ing.com) – nie wiemy, czy to podróbka
                if d <= _max_typo_dist(brand_sld, whole_sld) and TYPO_RISK_BY_DIST[d] > typo_risk:
                    typo_risk = TYPO_RISK_BY_DIST[d]
                    closest_brand = brand
        if typo_risk:
            risk = max(risk, typo_risk)
            reasons.append("TYPOSQUATTING_LEVENSHTEIN")

    # 3. DGA – entropia Shannona i proporcja spółgłosek do samogłosek.
    entropy = shannon_entropy(sld)
    letters = [c for c in sld if c.isalpha()]
    is_dga = entropy > ENTROPY_THRESHOLD
    if len(letters) >= MIN_LETTERS_FOR_RATIO:
        vowels = sum(c in VOWELS for c in letters)
        ratio = (len(letters) - vowels) / vowels if vowels else math.inf
        is_dga = is_dga or ratio > CONSONANT_VOWEL_THRESHOLD
    if not is_official and is_dga:
        risk = max(risk, DGA_RISK)
        reasons.append("DGA_HIGH_ENTROPY")

    if not reasons:
        risk = 0.0 if is_official else BASELINE_RISK

    return {
        "domain_risk": min(1.0, risk),
        "reason_codes": reasons,
        "details": {
            "is_punycode": is_punycode,
            "has_mixed_scripts": has_mixed_scripts,
            "min_levenshtein_dist": -1 if min_dist is None else min_dist,
            "closest_brand": closest_brand,
            "shannon_entropy": round(entropy, 3),
        },
    }
