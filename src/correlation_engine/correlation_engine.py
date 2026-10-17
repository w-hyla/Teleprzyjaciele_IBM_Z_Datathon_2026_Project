# Role: Module 4 - Correlation Engine
# Description: Handles weighted fusion and synergy rules to synthesize the final risk score[cite: 11].

class CorrelationEngine:
    """
    Combines outputs from domain_analyzer and transaction_analyzer.
    Outputs: final_score (float), action (str)[cite: 11].
    """

    def __init__(self):
        pass

    def calculate_final_risk(self, domain_result: dict, transaction_result: dict) -> dict:
        result = {
            "final_score": 0.0,
            "action": "ALLOW",  # "ALLOW" | "STEP_UP" | "DELAY" | "BLOCK"
            "override_triggered": False,
            "aggregated_reasons": []
        }

        if domain_result["domain_risk"] >= 0.9 or transaction_result["transaction_risk"] >= 0.85:
            result["override_triggered"] = True
            result["final_score"] = 1.0
            result["action"] = "BLOCK"
            result["aggregated_reasons"] = domain_result["reason_codes"] + transaction_result["reason_codes"]

            return result

        weighted_avg = domain_result["domain_risk"] * 0.45 + transaction_result["transaction_risk"] * 0.55
        final_score=0

        if domain_result["domain_risk"] >= 0. and transaction_result["transaction_risk"] >= 0.40:
            final_score = min(1.0, weighted_avg + 0,25)
        else:
            final_score = weighted_avg

        result["override_triggered"] = False

        if final_score < 0.35:
            result["action"] = "ALLOW"
        elif 0.35 <= final_score < 0.55:
            result["action"] = "STEP_UP"
        elif 0.55 <= final_score < 0.75:
            result["action"] = "DELAY"
        else:
            result["action"] = "BLOCK"

        result["aggregated_reasons"] = domain_result["reason_codes"] + domain_result["reason_codes"]

        return result