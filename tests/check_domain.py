"""Ręczne sprawdzanie dowolnych domen: werdykt fast_path + domain_risk z domain_analyzer.

python -m tests.check_domain mbank.pl mbamk.pl https://evil.top/login
python -m tests.check_domain < domeny.txt
"""

import argparse
import sys

from src.domain_analyzer import analyze
from src.fast_path import check


def format_result(domain: str, amount: float, avg: float, details: bool) -> str:
    fp = check({"domain": domain, "amount": amount, "history_avg_amount": avg})
    result = analyze(domain)
    line = (
        f"{domain:<32} risk={result['domain_risk']:.2f}  "
        f"fast_path={fp['verdict'] + ' (' + fp['reason_code'] + ')':<32} "
        f"reasons=[{', '.join(result['reason_codes'])}]"
    )
    if details:
        line += f"\n    {result['details']}"
    return line


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description="Wynik ryzyka dla podanych domen lub URL-i.")
    parser.add_argument("domains", nargs="*", help="domeny/URL-e; bez argumentów czyta ze stdin (jedna na linię)")
    parser.add_argument("--amount", type=float, default=100.0, help="kwota przelewu dla fast_path")
    parser.add_argument("--avg", type=float, default=100.0, help="średnia historyczna kwota dla fast_path")
    parser.add_argument("--details", action="store_true", help="wypisz też słownik details z domain_analyzer")
    args = parser.parse_args(argv)

    domains = args.domains or (line.strip() for line in sys.stdin)
    for domain in domains:
        if domain:
            print(format_result(domain, args.amount, args.avg, args.details), flush=True)


if __name__ == "__main__":
    main()
