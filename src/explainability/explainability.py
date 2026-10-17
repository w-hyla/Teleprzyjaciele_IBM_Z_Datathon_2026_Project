# Role: Module 5 - Explainability
# Description: Translates technical risk scores into simple language, recommended safety instructions, and audit logs[cite: 11, 19].
import datetime
from typing import Dict, Any, List

class ExplainabilityEngine:
    """
       Generates user intervention messages and audit logs based on a transaction's
       risk score and aggregated reasons.

       Attributes:
           PRIORITY_HIERARCHY (dict): Mapping of reason code -> priority rank (lower is higher priority).
           REASON_TEMPLATES (dict): Mapping of reason code -> template dict with
               ui_severity, user_title, user_message, recommended_action.
       """
    # Primary Reason Code Selection Hierarchy (Rank 1 is highest priority)
    PRIORITY_HIERARCHY = {
        "BLACKLISTED_PHISH": 1,
        "HOMOGLYPH_DETECTED": 1,
        "TYPOSQUATTING_LEVENSHTEIN": 1,
        "ACCOUNT_DRAIN_ZERO_BALANCE": 2,
        "MULE_DEST_ANOMALY": 3,
        "CROSS_LAYER_SYNERGY_PENALTY": 4,
        "UNUSUAL_AMOUNT": 4,
        "DGA_HIGH_ENTROPY": 5,
        "ONNX_ANOMALY_HIGH": 5,
        "HIGH_RISK_TX_TYPE": 5,
        "UNKNOWN_DOMAIN": 6,
        "LOW_RISK_PAYMENT": 6,
        "FALLBACK_TRIGGERED": 6,
        "UNKNOWN_REASON": 7  # Fallback
    }

    # Complete Reason Code Mapping Dictionary (Jargon-free, Senior-Friendly)
    REASON_TEMPLATES = {
        "BLACKLISTED_PHISH": {
            "ui_severity": "CRITICAL",
            "user_title": "Blacklisted Fake Site",
            "user_message": "This website ({domain}) has been reported as a password-stealing scam.",
            "recommended_action": "Close the page. Do not enter any data or SMS codes."
        },
        "HOMOGLYPH_DETECTED": {
            "ui_severity": "CRITICAL",
            "user_title": "Fake Website",
            "user_message": "The website address ({domain}) looks like your bank's name, but it contains hidden characters from another alphabet.",
            "recommended_action": "Close this page. Access the bank by typing the address manually or through the official app."
        },
        "TYPOSQUATTING_LEVENSHTEIN": {
            "ui_severity": "WARNING",
            "user_title": "Suspicious Website Address",
            "user_message": "There is a slight typo in the bank's website address ({domain}). This could be a fake site created by scammers.",
            "recommended_action": "Do not enter passwords or SMS codes. Carefully check the address in your browser."
        },
        "ACCOUNT_DRAIN_ZERO_BALANCE": {
            "ui_severity": "CRITICAL",
            "user_title": "Account Drain",
            "user_message": "This transfer for {formatted_amount} withdraws almost all your money at once. This is a typical method used by scammers.",
            "recommended_action": "If someone tells you to transfer savings to a 'safe account' – hang up, it is a scam attempt."
        },
        "MULE_DEST_ANOMALY": {
            "ui_severity": "CRITICAL",
            "user_title": "Suspicious Recipient Account",
            "user_message": "The recipient's account shows characteristics of a temporary account used by scammers.",
            "recommended_action": "Interrupt the transaction and consult the bank's hotline."
        },
        "CROSS_LAYER_SYNERGY_PENALTY": {
            "ui_severity": "WARNING",
            "user_title": "Unusual Operation",
            "user_message": "Combining an unknown website address ({domain}) with a transfer of {formatted_amount} falls outside your daily habits.",
            "recommended_action": "Hold off on the transfer. Consult this transfer with a family member or call the bank's hotline."
        },
        "UNUSUAL_AMOUNT": {
            "ui_severity": "WARNING",
            "user_title": "Unusually High Amount",
            "user_message": "The transfer amount of {formatted_amount} is significantly higher than your usual payments.",
            "recommended_action": "Carefully check the entered amount and recipient details before confirming."
        },
        "DGA_HIGH_ENTROPY": {
            "ui_severity": "WARNING",
            "user_title": "Suspicious Website Address",
            "user_message": "The website address ({domain}) consists of random characters and may be unsafe.",
            "recommended_action": "Do not continue the transaction on this page."
        },
        "ONNX_ANOMALY_HIGH": {
            "ui_severity": "WARNING",
            "user_title": "Unusual Transfer Pattern",
            "user_message": "The system detected an unusual execution of this transaction, resembling scam patterns.",
            "recommended_action": "Carefully verify if you are confirming the correct transfer."
        },
        "HIGH_RISK_TX_TYPE": {
            "ui_severity": "INFO",
            "user_title": "High-Risk Operation",
            "user_message": "You are making an external transfer or withdrawal that requires additional confirmation.",
            "recommended_action": "Ensure the recipient details are correct."
        },
        "FALLBACK_TRIGGERED": {
            "ui_severity": "WARNING",
            "user_title": "Additional System Verification",
            "user_message": "The security system is performing an extra check on your transaction.",
            "recommended_action": "Follow the instructions on the screen."
        },
        "UNKNOWN_REASON": {
            "ui_severity": "WARNING",
            "user_title": "Unusual Operation Detected",
            "user_message": "The transaction requires additional verification for safety reasons.",
            "recommended_action": "When in doubt, contact the bank."
        }
    }
    def __init__(self):
        """Initialize the ExplainabilityEngine.

               There are no constructor parameters at this time; templates and hierarchy
               are class-level constants.
               """
        pass

    def _format_currency(self, amount: float) -> str:
        """Format an amount into a human-friendly currency string.

        Uses a simple formatting that approximates a Polish locale: thousands
        separated by space and decimal comma, followed by "PLN".

        Args:
            amount (float): Numeric amount to format. If None, a placeholder is returned.

        Returns:
            str: Formatted currency string like "14 500,00 PLN" or "this amount" for None.
        """
        if amount is None:
            return "this amount"
        # Formatting to typical Polish locale (e.g., 14 500,00 PLN)
        return f"{amount:,.2f}".replace(",", " ").replace(".", ",") + " PLN"

    def _get_primary_reason(self, reasons: List[str]) -> str:
        """Resolve multiple technical reason codes into a single primary reason.

                Selection is based on the configured priority hierarchy. If the input list
                is empty the fallback "UNKNOWN_REASON" is returned.

                Args:
                    reasons (List[str]): List of aggregated technical reason codes.

                Returns:
                    str: The single primary reason code selected (lowest numeric rank).
                """
        if not reasons:
            return "UNKNOWN_REASON"

        # Sort available reasons by their priority rank; default to lowest priority if not found
        sorted_reasons = sorted(reasons, key=lambda r: self.PRIORITY_HIERARCHY.get(r, 99))
        return sorted_reasons[0]

    def _generate_audit_log(self, tx_id: str, score: float, action: str,
                            primary_reason: str, all_reasons: List[str]) -> str:
        """Constructs an unalterable single-line audit record for mainframe SIEM.

        Args:
            tx_id (str): The transaction ID.
            score (float): The final risk score.
            action (str): The action taken.
            primary_reason (str): The primary reason for the action.
            all_reasons (List[str]): All reasons for the action.

        Returns:
            str: The formatted audit log entry.
        """
        timestamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        reasons_csv = ",".join(all_reasons) if all_reasons else "NONE"

        return (f"[AUDIT] ID={tx_id} SCORE={score:.2f} | ACTION={action} | "
                f"PRIMARY_REASON={primary_reason} | REASONS={reasons_csv} | TS={timestamp}")

    def generate_explanation(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Transform pipeline output into a UI intervention payload and an audit trail.

        Expected payload keys:
            - transaction_id (str): Optional transaction id, default "UNKNOWN_TX".
            - action (str): Action taken by pipeline ("ALLOW", "DELAY", "BLOCK", ...).
            - final_score (float): Final numeric score.
            - aggregated_reasons (List[str]): Aggregated reason codes.
            - context (dict): Contextual values used for message templates, e.g. {"domain": "...", "amount": 123.0}.

        Args:
            payload (Dict[str, Any]): Pipeline response containing action, score, reasons and context.

        Returns:
            Dict[str, Any]: Dictionary with keys:
                - transaction_id (str)
                - user_intervention (dict): ui_severity, user_title, user_message, recommended_action
                - audit_trail (str): Single-line audit record
        """
        tx_id = payload.get("transaction_id", "UNKNOWN_TX")
        action = payload.get("action", "ALLOW")
        score = payload.get("final_score", 0.0)
        reasons = payload.get("aggregated_reasons", [])
        context = payload.get("context", {})

        # Short-Circuit for ALLOW Actions
        if action == "ALLOW":
            ui_response = {
                "ui_severity": "INFO",
                "user_title": "Transaction Safe",
                "user_message": "No warnings for the user.",
                "recommended_action": "None"
            }
            primary_reason = "KNOWN_BENIGN"
        else:
            # Select Primary Reason and Base Template
            primary_reason = self._get_primary_reason(reasons)
            template = self.REASON_TEMPLATES.get(primary_reason, self.REASON_TEMPLATES["UNKNOWN_REASON"])

            # Dynamic Context Injection
            domain = context.get("domain") or "this page"
            formatted_amount = self._format_currency(context.get("amount"))

            msg_text = template["user_message"].format(domain=domain, formatted_amount=formatted_amount)
            action_text = template["recommended_action"]

            # De-Escalation Protocol for DELAY Actions
            if action == "DELAY":
                anti_panic_prompt = " Your money is safe in the bank. You have 15 minutes to calmly think about it and contact someone you trust."
                msg_text += anti_panic_prompt

            ui_response = {
                "ui_severity": template["ui_severity"],
                "user_title": template["user_title"],
                "user_message": msg_text.strip(),
                "recommended_action": action_text
            }

        #Unified Payload Return
        return {
            "transaction_id": tx_id,
            "user_intervention": ui_response,
            "audit_trail": self._generate_audit_log(tx_id, score, action, primary_reason, reasons)
        }