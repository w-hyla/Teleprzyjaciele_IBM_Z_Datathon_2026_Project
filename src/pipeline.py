import os
import asyncio
import logging
from typing import Dict, Any

from .contracts import (
    PipelineRequest,
    CorrelationPayload,
    PipelineResponse,
)
from .collaborators import FallbackPolicy, LatencyTracker, AuditService

logger = logging.getLogger(__name__)


class FraudDetectionPipeline:
    """Orchestrates fast triage, deep analysis, scoring, and explainable output."""

    def __init__(self, fast_path, domain_analyzer, transaction_analyzer, correlation_engine, explainability, session_analyzer=None):
        """Initialize the pipeline with pluggable collaborators and runtime safety policies.

        Args:
            fast_path: Lightweight triage component for early allow/block shortcuts.
            domain_analyzer: Async analyzer for domain-level fraud indicators.
            transaction_analyzer: Async analyzer for transaction-level risk signals.
            correlation_engine: Component that combines analyzer outputs into a final score.
            explainability: Formatter for user-facing decisions and reasons.
            session_analyzer: Session-level analyzer for detecting session hijack/anomalies.
        """
        # External collaborators are injected so each module can be swapped independently.
        self.fast_path = fast_path
        self.domain_analyzer = domain_analyzer
        self.transaction_analyzer = transaction_analyzer
        self.correlation_engine = correlation_engine
        self.explainability = explainability
        self.session_analyzer = session_analyzer

        self.fallback_policy = FallbackPolicy()
        self.latency_tracker = LatencyTracker()
        self.audit_service = AuditService()

        # In production we fail open (resilience). In dev/test we fail fast (debuggability).
        env = os.getenv("PIPELINE_ENV", "production").lower()
        self.strict_mode = env in ("dev", "test")

    async def process_transaction(self, raw_payload: Dict[str, Any]) -> Dict[str, Any]:
        """Process one transaction payload from normalization to final explainable decision.

        The method runs fast-path triage first, then executes deep analyzers in parallel when
        needed, applies correlation scoring, and appends audit metadata.

        Args:
            raw_payload: Untrusted inbound payload containing transaction and user context.

        Returns:
            A fully formatted pipeline response including action, score, reasons, and audit trail.
        """
        self.latency_tracker.start_phase("total_pipeline")

        # 1) Normalize payload into a strongly-shaped request contract.
        tx_data = raw_payload.get("transaction", {})
        ctx_data = raw_payload.get("user_context", {})
        session_data = raw_payload.get("session_context", {})
        request: PipelineRequest = {
            "transaction_id": raw_payload.get("transaction_id", ""),
            "domain": raw_payload.get("domain", ""),
            "transaction": {
                "type": tx_data.get("type", ""),
                "amount": float(tx_data.get("amount", 0.0)),
                "oldbalanceOrg": float(tx_data.get("oldbalanceOrg", 0.0)),
                "newbalanceOrig": float(tx_data.get("newbalanceOrig", 0.0)),
                "oldbalanceDest": float(tx_data.get("oldbalanceDest", 0.0)),
                "newbalanceDest": float(tx_data.get("newbalanceDest", 0.0)),
            },
            "user_context": {
                "history_avg_amount": float(ctx_data.get("history_avg_amount", 0.0))
            }
            ,
            "session_context": {
                "session_id": session_data.get("session_id", ""),
                "ja3_hash": session_data.get("ja3_hash", ""),
                "ip_address": session_data.get("ip_address", ""),
                "asn": int(session_data.get("asn", 0)),
                "flow_duration": float(session_data.get("flow_duration", 0.0)),
                "flow_bytes_per_sec": float(session_data.get("flow_bytes_per_sec", 0.0)),
                "packet_rate": float(session_data.get("packet_rate", 0.0)),
            }
        }

        # 2) Fast-path triage for obvious allow/block decisions.
        self.latency_tracker.start_phase("fast_path")
        fp_verdict, bypass = self.fast_path.evaluate(
            request["domain"],
            request["transaction"]["amount"],
            request["user_context"]["history_avg_amount"]
        )
        self.latency_tracker.end_phase("fast_path")

        # Return immediately when triage is decisive to save latency and compute.
        if bypass:
            final_response = self.explainability.generate_direct_response(request["transaction_id"], fp_verdict)
            final_response["audit_trail"] = self.audit_service.format_audit_log(
                request["transaction_id"], final_response["action"], final_response.get("final_score", 0.0),
                final_response.get("aggregated_reasons", [])
            )
            self.latency_tracker.end_phase("total_pipeline")
            return final_response

        # 3) Run deep analyzers concurrently; degrade gracefully on operational failures.
        self.latency_tracker.start_phase("deep_check")

        async def safe_domain_analyze():
            """Run domain analysis with guarded fallback behavior.

            Expected operational failures map to a safe fallback result. Unexpected failures
            are raised in strict mode and masked by fallback in production mode.
            """
            try:
                return await self.domain_analyzer.analyze(request["domain"])
            except (asyncio.TimeoutError, ValueError) as e:
                # Expected runtime issues (e.g., timeout or malformed input).
                logger.warning(f"Operational failure in domain_analyzer: {e}")
                return self.fallback_policy.get_domain_fallback()
            except Exception as e:
                if self.strict_mode:
                    # In dev/test, surface unexpected bugs immediately.
                    logger.error(f"Strict Mode: Unexpected bug in domain_analyzer: {e}")
                    raise
                # In production, mask unexpected crashes with a safe fallback.
                logger.critical(f"Production Rescue: Unhandled exception in domain_analyzer masked by fallback: {e}")
                return self.fallback_policy.get_domain_fallback()

        async def safe_transaction_analyze():
            """Run transaction analysis with guarded fallback behavior.

            Expected operational failures map to a safe fallback result. Unexpected failures
            are raised in strict mode and masked by fallback in production mode.
            """
            try:
                return await self.transaction_analyzer.analyze(request["transaction"])
            except (asyncio.TimeoutError, RuntimeError, ValueError) as e:
                # Expected runtime issues (e.g., model load/inference failure).
                logger.warning(f"Operational failure in transaction_analyzer: {e}")
                return self.fallback_policy.get_transaction_fallback()
            except Exception as e:
                if self.strict_mode:
                    # In dev/test, keep exceptions visible for quick debugging.
                    logger.error(f"Strict Mode: Unexpected bug in transaction_analyzer: {e}")
                    raise
                # In production, protect pipeline availability with fallback scoring.
                logger.critical(
                    f"Production Rescue: Unhandled exception in transaction_analyzer masked by fallback: {e}")
                return self.fallback_policy.get_transaction_fallback()

        async def safe_session_analyze():
            """Run session analysis with guarded fallback behavior.

            The session analyzer is optional; if missing or failing we return a
            deterministic fallback to keep the pipeline available.
            """
            try:
                if not self.session_analyzer:
                    return self.fallback_policy.get_session_fallback()
                return await self.session_analyzer.analyze(request["session_context"])
            except Exception as e:
                # Deterministic fail-open handling in production
                logger.critical(f"Production Rescue: Unhandled exception in session_analyzer: {e}")
                return self.fallback_policy.get_session_fallback()

        domain_result, tx_result, session_result = await asyncio.gather(
            safe_domain_analyze(),
            safe_transaction_analyze(),
            safe_session_analyze(),
        )
        self.latency_tracker.end_phase("deep_check")

        # 4) Fuse analyzer outputs into a single decision payload.
        self.latency_tracker.start_phase("correlation")
        correlation_payload: CorrelationPayload = self.correlation_engine.evaluate(
            request["transaction_id"],
            domain_result,
            tx_result,
            context={
                "domain": request["domain"],
                "amount": request["transaction"]["amount"],
                "history_avg_amount": request["user_context"]["history_avg_amount"],
                "closest_brand": domain_result.get("details", {}).get("closest_brand")
            }
        )
        self.latency_tracker.end_phase("correlation")

        # 5) Build user-facing explanation and append audit metadata.
        self.latency_tracker.start_phase("explainability")
        final_response: PipelineResponse = self.explainability.format_response(correlation_payload)

        final_response["audit_trail"] = self.audit_service.format_audit_log(
            final_response["transaction_id"],
            final_response["action"],
            final_response["final_score"],
            final_response["aggregated_reasons"]
        )
        self.latency_tracker.end_phase("explainability")

        self.latency_tracker.end_phase("total_pipeline")
        return final_response