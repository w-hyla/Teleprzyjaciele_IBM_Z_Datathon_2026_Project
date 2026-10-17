import unittest

from src.domain_analyzer import analyze, levenshtein, shannon_entropy


class HelpersTest(unittest.TestCase):
    def test_levenshtein(self):
        self.assertEqual(levenshtein("mbank", "mbank"), 0)
        self.assertEqual(levenshtein("mbamk", "mbank"), 1)
        self.assertEqual(levenshtein("ailorbank", "aliorbank"), 2)
        self.assertEqual(levenshtein("", "abc"), 3)

    def test_shannon_entropy(self):
        self.assertEqual(shannon_entropy("aaaa"), 0.0)
        self.assertAlmostEqual(shannon_entropy("abcd"), 2.0)


class DomainAnalyzerTest(unittest.TestCase):
    def assertFlags(self, domain, reasons, risk):
        result = analyze(domain)
        self.assertEqual(result["reason_codes"], reasons, domain)
        self.assertAlmostEqual(result["domain_risk"], risk, msg=domain)
        return result

    def test_official_domain_has_zero_risk(self):
        result = self.assertFlags("mbank.pl", [], 0.0)
        self.assertEqual(result["details"]["closest_brand"], "mbank.pl")
        self.assertFlags("online.mbank.pl", [], 0.0)

    def test_output_matches_contract(self):
        result = analyze("example.com")
        self.assertEqual(set(result), {"domain_risk", "reason_codes", "details"})
        self.assertEqual(
            set(result["details"]),
            {"is_punycode", "has_mixed_scripts", "min_levenshtein_dist", "closest_brand", "shannon_entropy"},
        )

    def test_unknown_benign_domain_gets_baseline_risk(self):
        for domain in ("wikipedia.org", "stackoverflow.com", "bankier.pl"):
            self.assertFlags(domain, [], 0.05)

    def test_punycode_is_homoglyph(self):
        result = self.assertFlags("xn--mbnk-cta.pl", ["HOMOGLYPH_DETECTED", "TYPOSQUATTING_LEVENSHTEIN"], 0.95)
        self.assertTrue(result["details"]["is_punycode"])

    def test_mixed_scripts_is_homoglyph(self):
        result = analyze("mbаnk.pl")  # cyrylickie 'а'
        self.assertIn("HOMOGLYPH_DETECTED", result["reason_codes"])
        self.assertTrue(result["details"]["has_mixed_scripts"])
        self.assertEqual(result["domain_risk"], 0.95)

    def test_rn_looks_like_m(self):
        result = self.assertFlags("rnbank.pl", ["HOMOGLYPH_DETECTED"], 0.95)
        self.assertEqual(result["details"]["closest_brand"], "mbank.pl")

    def test_typosquatting_distance_one(self):
        self.assertFlags("mbamk.pl", ["TYPOSQUATTING_LEVENSHTEIN"], 0.90)
        self.assertFlags("pkobpp.pl", ["TYPOSQUATTING_LEVENSHTEIN"], 0.90)

    def test_typosquatting_distance_two(self):
        result = self.assertFlags("ailorbank.pl", ["TYPOSQUATTING_LEVENSHTEIN"], 0.70)
        self.assertEqual(result["details"]["min_levenshtein_dist"], 2)

    def test_brand_in_subdomain_contract_example(self):
        result = self.assertFlags("mbank.pl.weryfikacja-konta.top", ["TYPOSQUATTING_LEVENSHTEIN"], 0.90)
        self.assertEqual(result["details"]["closest_brand"], "mbank.pl")

    def test_brand_in_hyphenated_label(self):
        self.assertFlags("mbank-logowanie.pl", ["TYPOSQUATTING_LEVENSHTEIN"], 0.90)
        self.assertFlags("mbank-login.000webhostapp.com", ["TYPOSQUATTING_LEVENSHTEIN"], 0.90)

    def test_short_brands_and_common_words_do_not_match_fuzzily(self):
        self.assertFlags("bing.com", [], 0.05)  # 'ing'
        self.assertFlags("import.com", [], 0.05)  # 'inpost'
        self.assertFlags("bank.santanderconsumer.pl", [], 0.05)  # 'mbank'

    def test_same_sld_with_other_suffix_is_not_flagged(self):
        self.assertFlags("ing.com", [], 0.05)

    def test_dga(self):
        self.assertFlags("xk7q9zpw3mfl2vbn.com", ["DGA_HIGH_ENTROPY"], 0.75)

    def test_target_brands_override(self):
        self.assertFlags("mbank.pl", [], 0.0)
        result = analyze("paypa1.com", target_brands=["paypal.com"])
        self.assertEqual(result["reason_codes"], ["TYPOSQUATTING_LEVENSHTEIN"])


if __name__ == "__main__":
    unittest.main()
