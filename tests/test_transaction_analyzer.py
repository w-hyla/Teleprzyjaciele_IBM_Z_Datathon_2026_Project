from src.transaction_analyzer.transaction_analyzer import TransactionAnalyzer
from pathlib import Path
import logging
import unittest


logger = logging.getLogger(__name__)

class TestTransactionAnalyzer(unittest.TestCase):
    def setUp(self):

        project_root = Path(__file__).resolve().parents[1]  # path did not work, some ai fix
        model_file = project_root / "models" / "fraud_detect.onnx"

        if not model_file.exists():
            self.skipTest(f"ONNX model not found at {model_file}. Skipping TransactionAnalyzer tests.")

        self.model_path = str(model_file)
        self.analyzer = TransactionAnalyzer(model_path=self.model_path)

    def test_low_risk_payment(self):
        res = self.analyzer.analyze_transaction({"type": "PAYMENT", "amount": 50.0})
        self.assertAlmostEqual(res["transaction_risk"], 0.05, places=6)
        self.assertIn("LOW_RISK_PAYMENT", res["reason_codes"])

    def test_account_drain(self):
        payload = {
            "type": "TRANSFER",
            "amount": 9500.0,
            "oldbalanceOrg": 10000.0,
            "newbalanceOrig": 0.0,
            "oldbalanceDest": 1000.0,
            "newbalanceDest": 10500.0
        }
        res = self.analyzer.analyze_transaction(payload)
        self.assertTrue(res["details"].get("is_account_drain", False))
        self.assertIn("ACCOUNT_DRAIN_ZERO_BALANCE", res["reason_codes"])
        self.assertGreaterEqual(res["transaction_risk"], 0.85)

    def test_mule_destination_anomaly(self):
        payload = {
            "type": "TRANSFER",
            "amount": 2000.0,
            "oldbalanceOrg": 5000.0,
            "newbalanceOrig": 3000.0,
            "oldbalanceDest": 0.0,
            "newbalanceDest": 0.0
        }
        res = self.analyzer.analyze_transaction(payload)
        self.assertIn("MULE_DEST_ANOMALY", res["reason_codes"])

    def test_onnx_anomaly_high(self):
        """Verifies that high-risk transfers evaluated by ONNX trigger ONNX_ANOMALY_HIGH."""
        payload = {
            "type": "TRANSFER",
            "amount": 50000.0,
            "oldbalanceOrg": 50000.0,
            "newbalanceOrig": 0.0,
            "oldbalanceDest": 0.0,
            "newbalanceDest": 0.0
        }
        logger.info("Running %s with payload=%s", self._testMethodName, payload)
        res = self.analyzer.analyze_transaction(payload)
        logger.info("%s result=%s", self._testMethodName, res)
        self.assertIn("HIGH_RISK_TX_TYPE", res["reason_codes"])
        self.assertIn("ONNX_ANOMALY_HIGH", res["reason_codes"])
        self.assertGreaterEqual(res["details"]["onnx_score"], 0.70)

    def test_onnx_fallback_when_model_missing(self):
        """Tests fail-open resilience (0.50 score + FALLBACK_TRIGGERED) if ONNX fails."""
        broken_analyzer = TransactionAnalyzer(model_path="invalid_path.onnx")
        payload = {"type": "TRANSFER", "amount": 1000.0, "oldbalanceOrg": 2000.0}
        logger.info("Running %s with payload=%s", self._testMethodName, payload)
        res = broken_analyzer.analyze_transaction(payload)
        logger.info("%s result=%s", self._testMethodName, res)
        self.assertIn("FALLBACK_TRIGGERED", res["reason_codes"])
        self.assertEqual(res["details"]["onnx_score"], 0.50)

    def test_debit_and_cash_in_bypass(self):
        """Verifies that DEBIT and CASH_IN bypass deep inference just like PAYMENT."""
        for tx_type in ["DEBIT", "CASH_IN"]:
            payload = {"type": tx_type, "amount": 500.0}
            logger.info("Running %s with payload=%s", self._testMethodName, payload)
            res = self.analyzer.analyze_transaction(payload)
            logger.info("%s tx_type=%s result=%s", self._testMethodName, tx_type, res)
            self.assertAlmostEqual(res["transaction_risk"], 0.05, places=6)
            self.assertIn("LOW_RISK_PAYMENT", res["reason_codes"])

if __name__ == "__main__":
    unittest.main(verbosity=2)