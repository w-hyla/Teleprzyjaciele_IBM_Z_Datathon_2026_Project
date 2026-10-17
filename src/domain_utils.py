"""Wspólne narzędzia dla fast_path i domain_analyzer: parsowanie domen i ładowanie danych z data/."""

import csv
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

DATA_DIR = Path(__file__).resolve().parent.parent / "data"

# Biała lista fast_path i jednocześnie lista marek (target_brands) dla domain_analyzer.
TRUSTED_DOMAINS = frozenset({
    # Banki
    "mbank.pl", "pkobp.pl", "ipko.pl", "inteligo.pl", "ing.pl", "santander.pl",
    "pekao.com.pl", "pekao24.pl", "bankmillennium.pl", "aliorbank.pl", "bnpparibas.pl",
    "credit-agricole.pl", "citibank.pl", "citihandlowy.pl", "velobank.pl", "nestbank.pl",
    "bosbank.pl", "bankbps.pl", "bankpocztowy.pl", "plusbank.pl", "toyotabank.pl", "sgb.pl",
    # Płatności
    "blik.com", "payu.pl", "payu.com", "przelewy24.pl", "tpay.com",
    # Częste cele phishingu w PL
    "allegro.pl", "inpost.pl", "olx.pl",
})

# Uproszczenie zamiast pełnej Public Suffix List.
MULTI_PART_SUFFIXES = frozenset({
    "com.pl", "net.pl", "org.pl", "edu.pl", "gov.pl", "biz.pl", "info.pl",
    "co.uk", "org.uk", "ac.uk", "com.au", "net.au", "com.br", "co.za", "co.jp", "co.in", "com.cn",
})


def normalize_host(raw: str) -> str:
    """Zwraca sam host (małe litery, bez 'www.' i końcowej kropki) z URL-a lub gołej domeny."""
    raw = raw.strip()
    if "://" not in raw:
        raw = "//" + raw
    try:
        host = urlsplit(raw).hostname or ""
    except ValueError:
        return ""
    host = host.rstrip(".")
    if host.startswith("www."):
        host = host[4:]
    return host


def registrable_domain(host: str) -> str:
    """'a.b.mbank.pl' -> 'mbank.pl', 'x.pekao.com.pl' -> 'pekao.com.pl'."""
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_PART_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def split_host(host: str) -> tuple[list[str], str, str]:
    """Rozbija host na (etykiety subdomeny, SLD, sufiks): 'mbank.pl.evil.top' -> (['mbank', 'pl'], 'evil', 'top')."""
    reg = registrable_domain(host)
    sld, _, suffix = reg.partition(".")
    sub = host[: -len(reg)].rstrip(".")
    return (sub.split(".") if sub else []), sld, suffix


@lru_cache(maxsize=None)
def load_tranco(top_n: int) -> frozenset[str]:
    """Pierwsze top_n domen z rankingu Tranco (plik bez nagłówka: rank,domain; końce linii CRLF)."""
    domains = set()
    with open(DATA_DIR / "tranco_top_1m.csv", encoding="utf-8") as f:
        for i, line in enumerate(f):
            if i >= top_n:
                break
            domains.add(line.strip().partition(",")[2])
    return frozenset(domains)


@lru_cache(maxsize=None)
def load_phishtank_hosts() -> frozenset[str]:
    """Hosty wyciągnięte z pełnych URL-i w phishtank.csv."""
    with open(DATA_DIR / "phishtank.csv", encoding="utf-8", newline="") as f:
        hosts = {normalize_host(row["url"]) for row in csv.DictReader(f)}
    hosts.discard("")
    return frozenset(hosts)


@lru_cache(maxsize=None)
def load_homoglyph_map() -> dict[str, str]:
    """Mapa znak-homoglif -> łacińska mała litera, np. 'а' (cyrylica) -> 'a'."""
    with open(DATA_DIR / "homoglyphs.csv", encoding="utf-8", newline="") as f:
        return {row["homoglyph_char"]: row["target_char"].lower() for row in csv.DictReader(f)}
