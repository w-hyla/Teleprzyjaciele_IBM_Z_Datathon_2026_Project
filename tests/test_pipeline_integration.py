import asyncio
import copy
import statistics
import time
import unittest
from unittest import mock

from src.pipeline import PipelineOrchestrator, configure_logging


EXPECTED_KEYS = {
    "transaction_id",
    "action",
    "final_score",
    "override_triggered",
    "aggregated_reasons",
    "user_intervention",
    "audit_trail",
}
EXPECTED_INTERVENTION_KEYS = {"severity", "title", "message", "action_prompt"}

CONTRACT_PAYLOAD = {
    "transaction_id": "tx_987213812",
    "domain": "mbank.pl.weryfikacja-konta.top",
    "transaction": {
        "type": "TRANSFER",
        "amount": 14500.00,
        "oldbalanceOrg": 15000.00,
        "newbalanceOrig": 500.00,
        "oldbalanceDest": 0.00,
        "newbalanceDest": 0.00,
    },
    "user_context": {"history_avg_amount": 350.00},
}


def payload(domain, amount=100.0, history_avg_amount=350.0, transaction_id="tx_test_0001"):
    old_balance = 15000.0
    return {
        "transaction_id": transaction_id,
        "domain": domain,
        "transaction": {
            "type": "TRANSFER",
            "amount": amount,
            "oldbalanceOrg": old_balance,
            "newbalanceOrig": old_balance - amount,
            "oldbalanceDest": 0.0,
            "newbalanceDest": 0.0,
        },
        "user_context": {"history_avg_amount": history_avg_amount},
    }


def contract_payload():
    return copy.deepcopy(CONTRACT_PAYLOAD)


def allow_payload():
    return payload("mbank.pl", amount=100.0, history_avg_amount=350.0, transaction_id="tx_allow_0001")


def block_payload():
    return payload("http://allegro.pl.showitems.ca/oferta", transaction_id="tx_block_0001")


def _log_text(captured):
    return "\n".join(captured.output)


class PipelineIntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        configure_logging()
        cls.orch = PipelineOrchestrator(warm_up=True)

    # 1. Output schema
    def test_output_schema_matches_contract(self):
        result = self.orch.process_transaction(contract_payload())

        self.assertEqual(set(result.keys()), EXPECTED_KEYS)
        self.assertEqual(result["transaction_id"], "tx_987213812")
        self.assertEqual(set(result["user_intervention"].keys()), EXPECTED_INTERVENTION_KEYS)
        self.assertIsInstance(result["audit_trail"], str)
        self.assertTrue(result["audit_trail"].startswith("[AUDIT]"))
        self.assertIsInstance(result["final_score"], float)
        self.assertGreaterEqual(result["final_score"], 0.0)
        self.assertLessEqual(result["final_score"], 1.0)
        self.assertIsInstance(result["override_triggered"], bool)
        self.assertIsInstance(result["aggregated_reasons"], list)

    def test_output_schema_on_short_circuit(self):
        for p in (allow_payload(), block_payload()):
            with self.subTest(domain=p["domain"]):
                result = self.orch.process_transaction(p)
                self.assertEqual(set(result.keys()), EXPECTED_KEYS)
                self.assertEqual(set(result["user_intervention"].keys()), EXPECTED_INTERVENTION_KEYS)
                self.assertEqual(result["transaction_id"], p["transaction_id"])
                self.assertTrue(result["audit_trail"].startswith("[AUDIT]"))

    # 2. Short-circuit ALLOW
    def test_short_circuit_allow_skips_phase_two(self):
        domain_mock = mock.Mock(return_value={"domain_risk": 0.0, "reasons": []})
        tx_mock = mock.Mock()
        with mock.patch.object(self.orch, "domain_analyze", domain_mock), \
                mock.patch.object(self.orch, "tx_analyzer", tx_mock), \
                self.assertLogs("pipeline", level="INFO") as captured:
            result = self.orch.process_transaction(allow_payload())

        self.assertEqual(result["action"], "ALLOW")
        self.assertEqual(result["final_score"], 0.0)
        self.assertFalse(result["override_triggered"])
        self.assertIn("KNOWN_BENIGN", result["aggregated_reasons"])
        domain_mock.assert_not_called()
        tx_mock.analyze_transaction.assert_not_called()

        logs = _log_text(captured)
        self.assertIn("[SHORT-CIRCUIT]", logs)
        self.assertIn("[LATENCY]", logs)
        self.assertIn("[AUDIT]", logs)

    # 3. Short-circuit BLOCK
    def test_short_circuit_block_blacklisted_phish(self):
        domain_mock = mock.Mock(return_value={"domain_risk": 0.0, "reasons": []})
        with mock.patch.object(self.orch, "domain_analyze", domain_mock), \
                self.assertLogs("pipeline", level="INFO") as captured:
            result = self.orch.process_transaction(block_payload())

        self.assertEqual(result["action"], "BLOCK")
        self.assertEqual(result["final_score"], 1.0)
        self.assertTrue(result["override_triggered"])
        self.assertIn("BLACKLISTED_PHISH", result["aggregated_reasons"])
        domain_mock.assert_not_called()
        self.assertIn("[SHORT-CIRCUIT]", _log_text(captured))

    # 4. Contract payload (real modules end to end)
    def test_contract_payload_is_blocked_by_typosquatting_override(self):
        with self.assertLogs("pipeline", level="INFO") as captured:
            result = self.orch.process_transaction(contract_payload())

        self.assertEqual(result["action"], "BLOCK")
        self.assertTrue(result["override_triggered"])
        self.assertEqual(result["final_score"], 1.0)
        self.assertIn("TYPOSQUATTING_LEVENSHTEIN", result["aggregated_reasons"])

        logs = _log_text(captured)
        self.assertIn("[LATENCY]", logs)
        self.assertIn("[AUDIT]", logs)
        self.assertNotIn("[SHORT-CIRCUIT]", logs)

    # 5. Fallbacks
    def test_transaction_analyzer_failure_falls_back(self):
        tx_mock = mock.Mock()
        tx_mock.analyze_transaction.side_effect = RuntimeError("model exploded")
        with mock.patch.object(self.orch, "tx_analyzer", tx_mock), \
                self.assertLogs("pipeline", level="WARNING") as captured:
            result = self.orch.process_transaction(contract_payload())

        tx_mock.analyze_transaction.assert_called_once()
        self.assertEqual(set(result.keys()), EXPECTED_KEYS)
        self.assertIn("FALLBACK_TRIGGERED", result["aggregated_reasons"])
        self.assertIn("[WARNING] Fallback triggered", _log_text(captured))

    def test_missing_transaction_analyzer_falls_back(self):
        with mock.patch.object(self.orch, "tx_analyzer", None), \
                self.assertLogs("pipeline", level="WARNING") as captured:
            result = self.orch.process_transaction(contract_payload())

        self.assertEqual(set(result.keys()), EXPECTED_KEYS)
        self.assertIn("FALLBACK_TRIGGERED", result["aggregated_reasons"])
        self.assertIn("[WARNING] Fallback triggered", _log_text(captured))

    def test_domain_analyzer_failure_falls_back(self):
        domain_mock = mock.Mock(side_effect=RuntimeError("dns down"))
        with mock.patch.object(self.orch, "domain_analyze", domain_mock), \
                self.assertLogs("pipeline", level="WARNING") as captured:
            result = self.orch.process_transaction(contract_payload())

        domain_mock.assert_called_once()
        self.assertEqual(set(result.keys()), EXPECTED_KEYS)
        self.assertIn("FALLBACK_TRIGGERED", result["aggregated_reasons"])
        self.assertIn("[WARNING] Fallback triggered", _log_text(captured))

    def test_correlation_failure_falls_back_to_delay(self):
        corr_mock = mock.Mock()
        corr_mock.calculate_final_risk.side_effect = RuntimeError("bad weights")
        with mock.patch.object(self.orch, "correlation", corr_mock), \
                self.assertLogs("pipeline", level="WARNING") as captured:
            result = self.orch.process_transaction(contract_payload())

        corr_mock.calculate_final_risk.assert_called_once()
        self.assertEqual(set(result.keys()), EXPECTED_KEYS)
        self.assertEqual(result["action"], "DELAY")
        self.assertIn("FALLBACK_TRIGGERED", result["aggregated_reasons"])
        self.assertIn("[WARNING] Fallback triggered", _log_text(captured))

    def test_full_path_score_matches_weighted_fusion(self):
        # No override: final_score must be the 45/55 fusion, not the module's 0.0 placeholder.
        domain_mock = mock.Mock(return_value={"domain_risk": 0.20, "reason_codes": []})
        tx_mock = mock.Mock()
        tx_mock.analyze_transaction.return_value = {"transaction_risk": 0.40,
                                                    "reason_codes": ["HIGH_RISK_TX_TYPE"]}
        with mock.patch.object(self.orch, "domain_analyze", domain_mock), \
                mock.patch.object(self.orch, "tx_analyzer", tx_mock):
            result = self.orch.process_transaction(contract_payload())

        self.assertEqual(result["action"], "ALLOW")
        self.assertFalse(result["override_triggered"])
        self.assertAlmostEqual(result["final_score"], 0.31)
        self.assertIn("HIGH_RISK_TX_TYPE", result["aggregated_reasons"])

    def test_phase_two_timeout_falls_back(self):
        def slow_domain_analyze(domain):
            time.sleep(0.2)
            return {"domain_risk": 0.0, "reasons": []}

        with mock.patch.object(self.orch, "domain_analyze", slow_domain_analyze), \
                mock.patch.object(self.orch, "phase2_timeout_s", 0.05), \
                self.assertLogs("pipeline", level="WARNING") as captured:
            result = self.orch.process_transaction(contract_payload())

        self.assertEqual(set(result.keys()), EXPECTED_KEYS)
        self.assertIn("FALLBACK_TRIGGERED", result["aggregated_reasons"])
        self.assertIn("[WARNING] Fallback triggered", _log_text(captured))

    # 6. Sync wrapper
    def test_sync_wrapper_matches_async(self):
        for p in (allow_payload(), block_payload(), contract_payload()):
            with self.subTest(domain=p["domain"]):
                sync_result = self.orch.process_transaction(copy.deepcopy(p))
                async_result = asyncio.run(self.orch.process_transaction_async(copy.deepcopy(p)))
                sync_result.pop("audit_trail")
                async_result.pop("audit_trail")
                self.assertEqual(sync_result, async_result)

    # 7. SLA
    def test_short_circuit_latency_within_sla(self):
        p = allow_payload()
        self.orch.process_transaction(p)  # warm-up run
        timings_ms = []
        for _ in range(20):
            start = time.perf_counter()
            self.orch.process_transaction(p)
            timings_ms.append((time.perf_counter() - start) * 1000.0)

        self.assertLess(statistics.median(timings_ms), 25.0)


if __name__ == "__main__":
    unittest.main()
