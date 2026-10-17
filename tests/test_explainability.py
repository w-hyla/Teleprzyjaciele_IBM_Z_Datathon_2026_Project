import unittest
from typing import Dict, Any
from explainability import ExplainabilityEngine


class TestExplainabilityEngine(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """Initialize the Explainability Engine once for all tests."""
        cls.engine = ExplainabilityEngine()
        cls.base_tx_id = "tx_987213812"

    def _regression_generate_mock_payload(self, action: str, reasons: list[str], context: Dict[str, Any]) -> Dict[str, Any]:
        """Helper method to construct the Unified I/O API Contract payload"""
        return {
            "transaction_id": self.base_tx_id,
            "final_score": 0.85,
            "action": action,
            "aggregated_reasons": reasons,
            "context": context
        }

    def regression_test_allow_action_short_circuit(self):
        """
        Test that an 'ALLOW' action bypasses standard checks and returns an INFO severity
        with no warnings for the user, as defined in the execution flow
        """
        payload = self._regression_generate_mock_payload(
            action="ALLOW",
            reasons=[],
            context={"domain": "mbank.pl", "amount": 150.0}
        )

        result = self.engine.generate_explanation(payload)

        self.assertEqual(result["transaction_id"], self.base_tx_id)
        self.assertEqual(result["user_intervention"]["ui_severity"], "INFO")
        self.assertEqual(result["user_intervention"]["user_title"],
                         "Transaction Safe")  # Or 'Transakcja bezpieczna' depending on localization

    def regression_test_priority_hierarchy_resolution(self):
        """
        Test that the engine prevents cognitive overload by selecting the highest priority reason.
        ACCOUNT_DRAIN_ZERO_BALANCE (Rank 2) must override CROSS_LAYER_SYNERGY_PENALTY (Rank 4)
        """
        payload = self._regression_generate_mock_payload(
            action="BLOCK",
            reasons=["CROSS_LAYER_SYNERGY_PENALTY", "ACCOUNT_DRAIN_ZERO_BALANCE", "UNKNOWN_REASON"],
            context={"domain": "mbank.pl.weryfikacja.top", "amount": 14500.0}
        )

        result = self.engine.generate_explanation(payload)
        intervention = result["user_intervention"]

        # Verify it selected Rank 2 over Rank 4 and 6
        self.assertEqual(intervention["ui_severity"], "CRITICAL")
        self.assertEqual(intervention["user_title"], "Account Drain")  # Checks mapping dictionary

    def regression_test_dynamic_currency_and_domain_formatting(self):
        """
        Test that amounts are dynamically formatted into standard currency text (e.g., 14 500,00 PLN)
        and the domain is correctly injected into the user message
        """
        payload = self._regression_generate_mock_payload(
            action="BLOCK",
            reasons=["CROSS_LAYER_SYNERGY_PENALTY"],
            context={"domain": "mbank.pl.weryfikacja.top", "amount": 14500.0}
        )

        result = self.engine.generate_explanation(payload)
        message = result["user_intervention"]["user_message"]

        self.assertIn("mbank.pl.weryfikacja.top", message)
        self.assertIn("14 500,00 PLN", message)  # Verifies exact formatting required by engine output

    def regression_test_missing_context_fallbacks(self):
        """
        Test that missing amounts inject the generic fallback 'this amount' and missing domains
        inject 'this page' to ensure deterministic error handling
        """
        payload = self._regression_generate_mock_payload(
            action="BLOCK",
            reasons=["CROSS_LAYER_SYNERGY_PENALTY"],
            context={"domain": None, "amount": None}
        )

        result = self.engine.generate_explanation(payload)
        message = result["user_intervention"]["user_message"]

        self.assertIn("this page", message)
        self.assertIn("this amount", message)

    def regression_test_delay_action_deescalation_protocol(self):
        """
        Test the Anti-Panic Protocol. When action is 'DELAY', the module MUST append a calm,
        anti-panic mandate to break the scammer's false sense of urgency
        """
        payload = self._regression_generate_mock_payload(
            action="DELAY",
            reasons=["TYPOSQUATTING_LEVENSHTEIN"],
            context={"domain": "mbank.pl", "amount": 500.0}
        )

        result = self.engine.generate_explanation(payload)
        message = result["user_intervention"]["user_message"]

        # Verify the 15-minute pause anti-panic suffix is appended
        self.assertIn("safe in the bank", message)
        self.assertIn("15 minutes", message)

    def regression_test_audit_trail_siem_format(self):
        """
        Test that the module constructs an unalterable single-line audit record
        formatted for mainframe SIEM log ingestion (z/OS SMF or LinuxONE Syslog).
        """
        payload = self._regression_generate_mock_payload(
            action="DELAY",
            reasons=["ACCOUNT_DRAIN_ZERO_BALANCE", "CROSS_LAYER_SYNERGY_PENALTY"],
            context={"domain": "mbank.pl", "amount": 14500.0}
        )

        result = self.engine.generate_explanation(payload)
        audit_log = result["audit_trail"]

        # Verify standard structure: [AUDIT] ID=... SCORE=... | ACTION=... | PRIMARY_REASON=... | REASONS=... | TS=...
        self.assertTrue(audit_log.startswith("[AUDIT]"))
        self.assertIn(f"ID={self.base_tx_id}", audit_log)
        self.assertIn("SCORE=0.85", audit_log)
        self.assertIn("ACTION=DELAY", audit_log)
        self.assertIn("PRIMARY_REASON=ACCOUNT_DRAIN_ZERO_BALANCE", audit_log)
        self.assertIn("REASONS=ACCOUNT_DRAIN_ZERO_BALANCE,CROSS_LAYER_SYNERGY_PENALTY", audit_log)

        # Regex to check ISO 8601 timestamp format (e.g., TS=2026-10-17T03:38:19Z)
        self.assertRegex(audit_log, r"TS=\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")

    def setUp(self):
        # Baseline valid payload representing the expected input schema
        self.valid_payload: Dict[str, Any] = {
            "transaction_id": "tx_987213812",
            "final_score": 0.85,
            "action": "BLOCK",
            "aggregated_reasons": ["HOMOGLYPH_DETECTED"],
            "context": {
                "domain": "mbank.pl.weryfikacja.top",
                "amount": 14500.0,
                "history_avg_amount": 350.0,
                "closest_brand": "mbank.pl"
            }
        }

    def test_contract_and_schema_validation(self):
        """
        1. Contract & Schema Validation
        Verifies that the output strictly conforms to the expected dictionary schema.
        """
        result = self.engine.generate_explanation(self.valid_payload)
        self.assertIn("transaction_id", result)
        self.assertIn("user_intervention", result)
        self.assertIn("audit_trail", result)

        ui = result["user_intervention"]
        self.assertIn("ui_severity", ui)
        self.assertIn("user_title", ui)
        self.assertIn("user_message", ui)
        self.assertIn("recommended_action", ui)

    def test_decision_flow_allow_short_circuit(self):
        """
        2. Decision Flow: ALLOW Short-Circuiting
        Validates that ALLOW actions bypass deep logic and return INFO severity.
        """
        self.valid_payload["action"] = "ALLOW"
        self.valid_payload["final_score"] = 0.1
        self.valid_payload["aggregated_reasons"] = []

        result = self.engine.generate_explanation(self.valid_payload)

        self.assertEqual(result["user_intervention"]["ui_severity"], "INFO")
        self.assertEqual(result["user_intervention"]["user_title"], "Transaction Safe")

        self.assertEqual(result["user_intervention"]["user_message"], "No warnings for the user.")

    def test_decision_flow_priority_hierarchy_resolution(self):
        """
        2. Decision Flow: Priority Hierarchy Resolution
        Identity/phishing threats (HOMOGLYPH_DETECTED) must override AI/ONNX model anomalies.
        """
        self.valid_payload["action"] = "BLOCK"
        self.valid_payload["final_score"] = 0.95
        self.valid_payload["aggregated_reasons"] = ["ONNX_ANOMALY_HIGH", "HOMOGLYPH_DETECTED"]

        result = self.engine.generate_explanation(self.valid_payload)

        self.assertEqual(result["user_intervention"]["ui_severity"], "CRITICAL")
        self.assertEqual(result["user_intervention"]["user_title"], "Fake Website")

    def test_decision_flow_jargon_free_transformation(self):
        """
        2. Decision Flow: Jargon-Free Transformation
        Technical terms must be systematically eliminated from user-facing text.
        """
        self.valid_payload["aggregated_reasons"] = ["DGA_HIGH_ENTROPY", "HOMOGLYPH_DETECTED"]

        result = self.engine.generate_explanation(self.valid_payload)
        message = result["user_intervention"]["user_message"].lower()

        forbidden_words = ["homoglyph", "entropy", "onnx", "punycode"]
        for word in forbidden_words:
            self.assertNotIn(word, message, f"Jargon word '{word}' found in user message!")

    def test_decision_flow_anti_panic_de_escalation(self):
        """
        2. Decision Flow: Anti-Panic De-Escalation Protocol
        Validates the mandated 15-minute pause messaging for DELAY actions.
        """
        self.valid_payload["action"] = "DELAY"
        self.valid_payload["final_score"] = 0.72
        self.valid_payload["aggregated_reasons"] = ["ACCOUNT_DRAIN_ZERO_BALANCE"]

        result = self.engine.generate_explanation(self.valid_payload)

        expected_mandate = "your money is safe in the bank. you have 15 minutes to calmly think about it and contact someone you trust"
        combined_text = (result["user_intervention"]["user_message"] + " " + result["user_intervention"][
            "recommended_action"]).lower()

        self.assertIn(expected_mandate, combined_text, "De-escalation protocol missing from DELAY action output.")

    def test_dynamic_metadata_missing_fallbacks(self):
        """
        3. Dynamic Formatting & Fallback Handling
        Missing or null context metadata should inject generic fallback strings without crashing.
        """
        self.valid_payload["context"]: Dict[str, Any] = {
            "domain": None,
            "amount": None,
            "history_avg_amount": None,
            "closest_brand": None
        }

        result = self.engine.generate_explanation(self.valid_payload)
        message = result["user_intervention"]["user_message"].lower()

        self.assertTrue("this page" in message or "this website" in message)

    def test_edge_cases_contradictory_data(self):
        """
        4. Edge Cases: Contradictory Data Handling
        A high risk score paired with an ALLOW action must still execute short-circuit logic predictably.
        """
        self.valid_payload["action"] = "ALLOW"
        self.valid_payload["final_score"] = 0.99  # Contradictory high score
        self.valid_payload["aggregated_reasons"] = ["ACCOUNT_DRAIN_ZERO_BALANCE"]

        result = self.engine.generate_explanation(self.valid_payload)

        self.assertEqual(result["user_intervention"]["ui_severity"], "INFO")

    def test_edge_cases_unrecognized_inputs(self):
        """
        4. Edge Cases: Malformed or Unrecognized Inputs
        Unknown reasons should fallback gracefully without crashing the pipeline.
        """
        self.valid_payload["action"] = "STEP_UP"
        self.valid_payload["final_score"] = 0.6
        self.valid_payload["aggregated_reasons"] = ["COMPLETELY_MADE_UP_ERROR_CODE"]

        result = self.engine.generate_explanation(self.valid_payload)

        self.assertEqual(result["user_intervention"]["ui_severity"], "WARNING")
        self.assertEqual(result["user_intervention"]["user_title"], "Unusual Operation Detected")
        self.assertIn("safety reasons", result["user_intervention"]["user_message"].lower())

    def test_audit_trail_telemetry_integrity(self):
        """
        5. Audit Trail Telemetry Integrity
        Ensure the audit trail is a single-line record suitable for SIEM log ingestion.
        """
        self.valid_payload["transaction_id"] = "tx_log1"
        self.valid_payload["action"] = "DELAY"
        self.valid_payload["final_score"] = 0.72

        result = self.engine.generate_explanation(self.valid_payload)
        audit = result["audit_trail"]

        self.assertNotIn("\n", audit)
        self.assertIn("ID=tx_log1", audit)
        self.assertIn("SCORE=0.72", audit)
        self.assertIn("ACTION=DELAY", audit)


if __name__ == "__main__":
    unittest.main(verbosity=2)
