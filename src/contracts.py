"""Shared typed contracts for pipeline I/O and inter-module communication.

These `TypedDict` definitions keep module boundaries explicit and make payload
shapes easier to validate during rapid hackathon iteration.
"""

from typing import TypedDict, List, Optional


# 1) Pipeline request (global inbound payload)
class TransactionData(TypedDict):
    """Core transaction features consumed by the transaction analyzer."""

    type: str
    amount: float
    oldbalanceOrg: float
    newbalanceOrig: float
    oldbalanceDest: float
    newbalanceDest: float


class UserContext(TypedDict):
    """User history signals used for relative risk heuristics."""

    history_avg_amount: float

class SessionContext(TypedDict):
    """Optional session-level signals captured at ingestion.

    Fields are lightweight and intended for auxiliary heuristics (session
    hijack detection, flow anomalies) rather than primary transaction scoring.
    """

    session_id: str
    ja3_hash: str
    ip_address: str
    asn: int
    flow_duration: float
    flow_bytes_per_sec: float
    packet_rate: float


class PipelineRequest(TypedDict):
    """Normalized request shape expected by the pipeline orchestrator."""
    transaction_id: str
    domain: str
    transaction: TransactionData
    user_context: UserContext
    session_context: SessionContext


# 2) Domain analyzer result
class DomainDetails(TypedDict):
    """Low-level domain indicators used to explain domain risk."""

    is_punycode: bool
    has_mixed_scripts: bool
    min_levenshtein_dist: int
    closest_brand: Optional[str]
    shannon_entropy: float


class DomainResult(TypedDict):
    """Domain analyzer output with score, reasons, and diagnostics."""

    domain_risk: float
    reason_codes: List[str]
    details: DomainDetails


# 3) Transaction analyzer result
class TransactionDetails(TypedDict):
    """Low-level transaction indicators used to explain transaction risk."""

    onnx_score: float
    drain_ratio: float
    is_account_drain: bool
    is_high_risk_type: bool
    dest_balance_anomaly: bool


class TransactionResult(TypedDict):
    """Transaction analyzer output with score, reasons, and diagnostics."""

    transaction_risk: float
    reason_codes: List[str]
    details: TransactionDetails


# 4) Correlation and explainability input
class ExplainabilityContext(TypedDict):
    """Context fields propagated to explanation/audit layers."""

    domain: Optional[str]
    amount: Optional[float]
    history_avg_amount: Optional[float]
    closest_brand: Optional[str]


class CorrelationPayload(TypedDict):
    """Merged scoring payload produced by the correlation engine."""

    transaction_id: str
    final_score: float
    action: str
    aggregated_reasons: List[str]
    context: ExplainabilityContext


# 5) Final pipeline response
class UserIntervention(TypedDict):
    """User-facing intervention content shown for risky transactions."""

    severity: str
    title: str
    message: str
    action_prompt: str


class PipelineResponse(TypedDict):
    """Final API contract returned by the fraud detection pipeline."""

    transaction_id: str
    action: str
    final_score: float
    override_triggered: bool
    aggregated_reasons: List[str]
    user_intervention: UserIntervention
    audit_trail: str


class SessionDetails(TypedDict):
    """Low-level session indicators used for session-risk scoring.

    - ja3_shift_detected: whether TLS fingerprint (JA3) changed mid-session
    - asn_shift_detected: whether ASN changed for the session IPs
    - onnx_flow_anomaly_score: model-produced flow anomaly score (0.0-1.0)
    - baseline_ip_match: whether the IP matches the user's baseline fingerprint
    """

    ja3_shift_detected: bool
    asn_shift_detected: bool
    onnx_flow_anomaly_score: float
    baseline_ip_match: bool


class SessionResult(TypedDict):
    """Session analyzer output with aggregated session risk and reasons."""

    session_risk: float
    reason_codes: List[str]
    details: SessionDetails