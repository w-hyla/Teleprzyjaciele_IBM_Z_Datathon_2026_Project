"""Shared helper services used by the fraud detection pipeline.

This module contains lightweight collaborators for fallback outputs, latency
measurement, and deterministic audit logging.
"""

import time
import logging
from typing import List
from .contracts import DomainResult, TransactionResult, SessionResult

# Bind to the operational logger namespace configured by logging settings.
logger = logging.getLogger("pipeline.operational")


class FallbackPolicy:
    """Provides safe default results when analyzers fail at runtime."""

    def get_transaction_fallback(self) -> TransactionResult:
        """Return a conservative transaction result used on analyzer failure."""
        return {
            "transaction_risk": 0.50,
            "reason_codes": ["FALLBACK_TRIGGERED"],
            "details": {
                "onnx_score": 0.50,
                "drain_ratio": 0.0,
                "is_account_drain": False,
                "is_high_risk_type": False,
                "dest_balance_anomaly": False
            }
        }

    def get_domain_fallback(self) -> DomainResult:
        """Return a low-risk domain result when domain checks are unavailable."""
        return {
            "domain_risk": 0.05,
            "reason_codes": ["UNKNOWN_DOMAIN"],
            "details": {
                "is_punycode": False,
                "has_mixed_scripts": False,
                "min_levenshtein_dist": 0,
                "closest_brand": None,
                "shannon_entropy": 0.0
            }
        }

    def get_session_fallback(self) -> SessionResult:
        """Return a conservative session result used when session analysis fails."""
        return {
            "session_risk": 0.50,
            "reason_codes": ["FALLBACK_SESSION"],
            "details": {
                "ja3_shift_detected": False,
                "asn_shift_detected": False,
                "onnx_flow_anomaly_score": 0.50,
                "baseline_ip_match": True,
            },
        }


class LatencyTracker:
    """Tracks phase timings and emits SLA-oriented operational logs."""

    def __init__(self):
        """Initialize per-phase start timestamps."""
        self.start_times = {}

    def start_phase(self, phase_name: str):
        """Mark the start time for a named processing phase."""
        self.start_times[phase_name] = time.perf_counter()

    def end_phase(self, phase_name: str):
        """Close a phase timer and log latency against the 25 ms budget."""
        if phase_name in self.start_times:
            elapsed_ms = (time.perf_counter() - self.start_times[phase_name]) * 1000

            if elapsed_ms > 25.0:
                logger.warning(f"SLA Breach in {phase_name}: {elapsed_ms:.2f} ms (Budget: < 25 ms)")
            else:
                logger.debug(f"Phase {phase_name} completed in {elapsed_ms:.2f} ms")


class AuditService:
    """Formats and writes deterministic audit lines for compliance and tracing."""

    def __init__(self):
        """Bind to the dedicated audit logger for stable, isolated output."""
        # Use a dedicated logger to keep audit events separate from operational noise.
        self.audit_logger = logging.getLogger("pipeline.audit")

    def format_audit_log(self, transaction_id: str, action: str, score: float, reasons: List[str]) -> str:
        """Build and emit a canonical audit line, then return it.

        Args:
            transaction_id: Unique transaction identifier.
            action: Final pipeline action (e.g., ALLOW, REVIEW, BLOCK).
            score: Final risk score associated with the action.
            reasons: Aggregated reason codes explaining the decision.

        Returns:
            The exact audit line emitted to the audit logger.
        """
        reasons_str = ",".join(reasons) if reasons else "NONE"
        audit_line = f"[AUDIT] ID={transaction_id} SCORE={score:.2f} ACTION={action} REASONS={reasons_str}"

        # Write deterministically to audit handlers (e.g., pipeline_audit.log).
        self.audit_logger.info(audit_line)

        return audit_line