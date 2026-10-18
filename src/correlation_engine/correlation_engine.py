# Role: Module 4 - Correlation Engine
# Description: Handles weighted fusion and synergy rules to synthesize the final risk score[cite: 11].
from typing import List, cast

from src.contracts import (
    CorrelationPayload,
    DomainResult,
    ExplainabilityContext,
    SessionResult,
    TransactionResult,
)


class CorrelationEngine:
    """
    Combines outputs from domain_analyzer and transaction_analyzer.
    Outputs: final_score (float), action (str).
    """

    def evaluate(
        self,
        transaction_id: str,
        domain_result: DomainResult,
        tx_result: TransactionResult,
        session_result: SessionResult,
        context: ExplainabilityContext,
    ) -> CorrelationPayload:
        # Extract risk scores safely
        domain_risk = domain_result.get("domain_risk", 0.0)
        tx_risk = tx_result.get("transaction_risk", 0.0)
        session_risk = session_result.get("session_risk", 0.0)

        # Fixed Bug: Safely aggregate reasons across all 3 layers
        aggregated_reasons: List[str] = (
            domain_result.get("reason_codes", [])
            + tx_result.get("reason_codes", [])
            + session_result.get("reason_codes", [])
        )

        # 1. Critical Override (Immediate BLOCK)
        # If any single layer detects an extreme threat, short-circuit the math.
        if domain_risk >= 0.90 or tx_risk >= 0.85 or session_risk >= 0.85:
            return {
                "transaction_id": transaction_id,
                "final_score": 1.0,
                "action": "BLOCK",
                "aggregated_reasons": aggregated_reasons + ["CRITICAL_OVERRIDE_TRIGGERED"],
                "context": context,
            }

        # 2. 3-Way Weighted Fusion
        # Distributing the 100% weight across the 3 dimensions of risk
        weighted_avg = (domain_risk * 0.30) + (session_risk * 0.30) + (tx_risk * 0.40)
        final_score = weighted_avg

        # 3. Synergy Penalties (Cross-Layer Anomalies)[cite: 2]
        # Synergy A: Odd transaction executed from a slightly suspicious domain
        if domain_risk >= 0.40 and tx_risk >= 0.40:
            final_score += 0.15
            aggregated_reasons.append("CROSS_LAYER_SYNERGY_PENALTY")

        # Synergy B: AiTM Hijack - Odd transaction from a shifted JA3/ASN session footprint
        if session_risk >= 0.70 and tx_risk >= 0.40:
            final_score += 0.25
            aggregated_reasons.append("SESSION_HIJACK_SYNERGY")

        # Ensure the score never breaks the 1.0 ceiling
        final_score = min(1.0, final_score)

        # 4. Action Resolution Matrix[cite: 2]
        if final_score < 0.35:
            action = "ALLOW"
        elif final_score < 0.55:
            action = "STEP_UP"
        elif final_score < 0.75:
            action = "DELAY"  # Triggers the 15-minute anti-panic de-escalation protocol[cite: 4]
        else:
            action = "BLOCK"

        # Adheres strictly to the CorrelationPayload TypedDict contract[cite: 2]
        return {
            "transaction_id": transaction_id,
            "final_score": round(final_score, 2),
            "action": action,
            "aggregated_reasons": aggregated_reasons,
            "context": context,
        }

    def calculate_final_risk(self, domain_result: dict, transaction_result: dict) -> dict:
        """Backward-compatible shim for older callers.

        This preserves the previous two-input API used by the package bootstrap
        while delegating to the newer three-layer evaluator with empty session
        signals and a minimal explainability context.
        """
        payload = self.evaluate(
            transaction_id="",
            domain_result=cast(DomainResult, cast(object, domain_result)),
            tx_result=cast(TransactionResult, cast(object, transaction_result)),
            session_result=cast(
                SessionResult,
                cast(
                    object,
                    {
                        "session_risk": 0.0,
                        "reason_codes": [],
                        "details": {
                            "ja3_shift_detected": False,
                            "asn_shift_detected": False,
                            "onnx_flow_anomaly_score": 0.0,
                            "baseline_ip_match": True,
                        },
                    },
                ),
            ),
            context={"domain": None, "amount": None, "history_avg_amount": None, "closest_brand": None},
        )
        return {
            "final_score": payload["final_score"],
            "action": payload["action"],
            "override_triggered": payload["action"] == "BLOCK" and "CRITICAL_OVERRIDE_TRIGGERED" in payload["aggregated_reasons"],
            "aggregated_reasons": payload["aggregated_reasons"],
        }
