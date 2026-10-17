# Role: Module 3 - Transaction Analyzer
# Description: Evaluates behavioral risks using PaySim domain knowledge and ONNX inferencing natively on LinuxONE. Accounts for 55% of the risk engine weight
import math
import logging
import numpy as np
import onnxruntime as ort
from typing import Dict, Any, List, Union, Tuple

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class TransactionAnalyzer:
    """
    Analyzes transaction features for Account Drain and Mule Account anomalies.
    Input: PaySim features
    Output: transaction_risk (float), reason_codes (list[str])
    """

    def __init__(self, model_path: str = "models/fraud_detect.onnx"):
        self.model_path = model_path
        self.epsilon = 1e-9  # Prevents ZeroDivisionError when calculating ratios
        self.ort_session = None
        try:
            self.ort_session = ort.InferenceSession(self.model_path)
            logger.info(f"Successfully loaded ONNX model from {self.model_path} for s390x execution.")
        except Exception as e:
            logger.error(f"Failed to load ONNX model at {self.model_path}: {e}")

    def _encode_transaction_type(self, tx_type: str) -> float:
        """
        Helper method to encode string transaction types into numeric features
        for the ONNX model input vector.
        """
        mapping = {"TRANSFER": 1.0, "CASH_OUT": 2.0, "PAYMENT": 3.0, "DEBIT": 4.0, "CASH_IN": 5.0}
        return mapping.get(tx_type, 0.0)

    def _run_onnx_inference(self, tx_type: str, amount: float, old_balance_org: float,
                            new_balance_orig: float, old_balance_dest: float,
                            new_balance_dest: float, drain_ratio: float) -> Tuple[float, bool]:
        """
        Executes ONNX inference and returns (onnx_score, fallback_triggered). Mainly for tests.
        """
        if self.ort_session is None:
            return 0.50, True

        try:
            type_enc = self._encode_transaction_type(tx_type)
            log_amount = math.log1p(amount)

            input_vector = [[
                type_enc,
                log_amount,
                old_balance_org,
                new_balance_orig,
                old_balance_dest,
                new_balance_dest,
                drain_ratio
            ]]

            input_data = np.array(input_vector, dtype=np.float32)
            input_name = self.ort_session.get_inputs()[0].name
            output_name = self.ort_session.get_outputs()[0].name

            predictions = self.ort_session.run([output_name], {input_name: input_data})
            onnx_score = float(np.squeeze(predictions[0]))
            return onnx_score, False

        except Exception as e:
            logger.warning(f"ONNX inference failed: {e}. Executing fallback mechanism.")
            return 0.50, True

    def analyze_transaction(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluates a single transaction against domain rules and the ONNX model.

        Input:
            payload (dict): Expected keys: type, amount, oldbalanceOrg, newbalanceOrig,
                            oldbalanceDest, newbalanceDest.
        Output:
            dict containing transaction_risk, reason_codes, and details payload.
        """
        reason_codes: List[str] = []

        # 1. Parse Input Payload
        tx_type = str(payload.get("type", ""))
        amount = float(payload.get("amount", 0.0))
        old_balance_org = float(payload.get("oldbalanceOrg", 0.0))
        new_balance_orig = float(payload.get("newbalanceOrig", 0.0))
        old_balance_dest = float(payload.get("oldbalanceDest", 0.0))
        new_balance_dest = float(payload.get("newbalanceDest", 0.0))

        # Initialize details dictionary
        details: Dict[str, Union[float, bool]] = {
            "onnx_score": 0.0,
            "drain_ratio": 0.0,
            "is_account_drain": False,
            "is_high_risk_type": False,
            "dest_balance_anomaly": False
        }

        #Transaction Type Filtering (PaySim Domain Knowledge)
        # 100% of confirmed frauds in PaySim occur in TRANSFER or CASH_OUT.
        if tx_type not in ["TRANSFER", "CASH_OUT"]:
            # Early return to save CPU cycles on LinuxONE
            return {
                "transaction_risk": 0.05,
                "reason_codes": ["LOW_RISK_PAYMENT"],
                "details": details
            }

        details["is_high_risk_type"] = True
        reason_codes.append("HIGH_RISK_TX_TYPE")

        # Zero-Balance Drain Detection
        # Calculate how much of the original balance is being transferred
        drain_ratio = amount / (old_balance_org + self.epsilon)
        details["drain_ratio"] = float(drain_ratio)

        drain_risk = 0.0
        # Critical condition: >= 85% drained and remaining balance <= 5%
        if drain_ratio >= 0.85 and new_balance_orig <= (0.05 * old_balance_org):
            details["is_account_drain"] = True
            drain_risk = 0.85
            reason_codes.append("ACCOUNT_DRAIN_ZERO_BALANCE")

        # Mule Account Verification (Destination Anomaly)
        # Receiving large amount but balance remains 0 implies technical/transit account
        if amount > 0 and old_balance_dest == 0.0 and new_balance_dest == 0.0:
            details["dest_balance_anomaly"] = True
            reason_codes.append("MULE_DEST_ANOMALY")

        # ONNX inference via helper with deterministic fallback handling
        onnx_score, fallback_triggered = self._run_onnx_inference(
            tx_type,
            amount,
            old_balance_org,
            new_balance_orig,
            old_balance_dest,
            new_balance_dest,
            drain_ratio,
        )
        details["onnx_score"] = onnx_score

        if fallback_triggered:
            reason_codes.append("FALLBACK_TRIGGERED")
        elif onnx_score >= 0.70:
            reason_codes.append("ONNX_ANOMALY_HIGH")

        # 6. Final Transaction Risk Calculation
        # Deterministic aggregation protecting against model failure
        transaction_risk = min(1.0, max(onnx_score, drain_risk))

        return {
            "transaction_risk": float(transaction_risk),
            "reason_codes": reason_codes,
            "details": details
        }