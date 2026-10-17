import unittest

from src.fast_path import build_blacklist, check


def payload(domain, amount=100.0, history_avg_amount=350.0):
    return {"domain": domain, "amount": amount, "history_avg_amount": history_avg_amount}


class FastPathTest(unittest.TestCase):
    def test_trusted_domain_with_normal_amount_is_allowed(self):
        self.assertEqual(
            check(payload("mbank.pl")),
            {"verdict": "ALLOW", "reason_code": "KNOWN_BENIGN", "bypass_pipeline": True},
        )

    def test_trusted_subdomain_and_full_url_are_normalized(self):
        self.assertEqual(check(payload("https://www.online.mbank.pl/login?x=1"))["verdict"], "ALLOW")

    def test_amount_exactly_at_threshold_is_allowed(self):
        self.assertEqual(check(payload("pkobp.pl", amount=525.0))["verdict"], "ALLOW")

    def test_trusted_domain_with_unusual_amount_goes_to_deep_check(self):
        self.assertEqual(
            check(payload("mbank.pl", amount=14500.0)),
            {"verdict": "DEEP_CHECK", "reason_code": "UNUSUAL_AMOUNT", "bypass_pipeline": False},
        )

    def test_brand_in_subdomain_is_not_trusted(self):
        result = check(payload("mbank.pl.weryfikacja-konta.top"), blacklist=frozenset())
        self.assertEqual(result["reason_code"], "UNKNOWN_DOMAIN")

    def test_phishtank_host_is_blocked(self):
        self.assertEqual(
            check(payload("http://allegro.pl.showitems.ca/oferta")),
            {"verdict": "BLOCK", "reason_code": "BLACKLISTED_PHISH", "bypass_pipeline": True},
        )

    def test_subdomain_of_blacklisted_domain_is_blocked(self):
        self.assertEqual(check(payload("login.evil.example"), blacklist=frozenset({"evil.example"}))["verdict"], "BLOCK")

    def test_popular_shared_hosts_are_not_blacklisted(self):
        blacklist = build_blacklist()
        for host in ("sites.google.com", "drive.google.com", "bit.ly", "goo.gl"):
            self.assertNotIn(host, blacklist)
        self.assertEqual(check(payload("sites.google.com"))["verdict"], "DEEP_CHECK")

    def test_unknown_domain_goes_to_deep_check(self):
        self.assertEqual(
            check(payload("wikipedia.org")),
            {"verdict": "DEEP_CHECK", "reason_code": "UNKNOWN_DOMAIN", "bypass_pipeline": False},
        )


if __name__ == "__main__":
    unittest.main()
