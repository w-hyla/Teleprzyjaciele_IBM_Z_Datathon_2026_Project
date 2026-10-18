"""Package bootstrap for pipeline startup.

This module configures logging for interactive/demonstration runs.
It intentionally does not instantiate heavyweight pipeline objects at import
time (those require real collaborators). Use :func:`create_pipeline` to
build an application-ready pipeline when needed.
"""

from typing import cast

from src.contracts import ExplainabilityContext, SessionResult
from src.logging_config import setup_logging

# Configure loggers/handlers before any pipeline components emit logs.
setup_logging()


def create_pipeline(fast_path=None, domain_analyzer=None, transaction_analyzer=None,
					correlation_engine=None, explainability=None):
	"""Build and return a lazily wired :class:`FraudDetectionPipeline`.

	Callers may inject custom collaborators. When a collaborator is ``None``,
	the factory wraps existing module implementations into the adapter interface
	expected by the orchestrator.

	Args:
		fast_path: Optional fast-path evaluator implementing ``evaluate(...)``.
		domain_analyzer: Optional async domain analyzer implementing ``analyze(...)``.
		transaction_analyzer: Optional async transaction analyzer implementing ``analyze(...)``.
		correlation_engine: Optional correlator implementing ``evaluate(...)``.
		explainability: Optional formatter implementing pipeline explainability methods.

	Returns:
		A fully constructed ``FraudDetectionPipeline`` instance.
	"""
	# Import inside the factory to keep top-level import lightweight.
	from pipeline import FraudDetectionPipeline

	# Lazy defaults: wrap existing modules into the adapter interfaces expected by the pipeline.
	if fast_path is None:
		from fast_path.fast_path import check as _fp_check

		class _FPWrapper:
			"""Adapter exposing the fast-path ``check`` function as ``evaluate``."""

			def evaluate(self, domain, amount, history_avg_amount):
				"""Return fast-path verdict and bypass flag for a normalized request."""
				res = _fp_check({"domain": domain, "amount": amount, "history_avg_amount": history_avg_amount})
				return res.get("verdict"), bool(res.get("bypass_pipeline", False))

		fast_path = _FPWrapper()

	if domain_analyzer is None:
		from domain_analyzer import analyze as _domain_analyze

		class _DomainAdapter:
			"""Adapter exposing synchronous domain analysis via an async method."""

			async def analyze(self, domain):
				"""Analyze one domain string and return a ``DomainResult`` payload."""
				return _domain_analyze(domain)

		domain_analyzer = _DomainAdapter()

	if transaction_analyzer is None:
		from transaction_analyzer import TransactionAnalyzer as _TxImpl

		class _TxAdapter:
			"""Adapter bridging ``TransactionAnalyzer`` to pipeline async interface."""

			def __init__(self):
				"""Create and hold the underlying transaction analyzer implementation."""
				self._impl = _TxImpl()

			async def analyze(self, payload):
				"""Analyze transaction payload and return transaction risk details."""
				return self._impl.analyze_transaction(payload)

		transaction_analyzer = _TxAdapter()

	if correlation_engine is None:
		from correlation_engine.correlation_engine import CorrelationEngine as _CorrImpl

		class _CorrAdapter:
			"""Adapter converting correlation engine output into pipeline contract shape."""

			def __init__(self):
				"""Create and hold the underlying correlation implementation."""
				self._impl = _CorrImpl()

			def evaluate(self, tx_id, domain_result, tx_result, session_result=None, context=None):
				"""Compute final risk and return a ``CorrelationPayload``-compatible dict."""
				if session_result is None:
					session_result = {
						"session_risk": 0.0,
						"reason_codes": [],
						"details": {
							"ja3_shift_detected": False,
							"asn_shift_detected": False,
							"onnx_flow_anomaly_score": 0.0,
							"baseline_ip_match": True,
						},
					}
				res = self._impl.evaluate(
					tx_id,
					domain_result,
					tx_result,
					cast(SessionResult, cast(object, session_result)),
					cast(ExplainabilityContext, cast(object, context or {
						"domain": None,
						"amount": None,
						"history_avg_amount": None,
						"closest_brand": None,
					})),
				)
				return {
					"transaction_id": tx_id,
					"final_score": float(res.get("final_score", 0.0)),
					"action": res.get("action", "ALLOW"),
					"override_triggered": "CRITICAL_OVERRIDE_TRIGGERED" in res.get("aggregated_reasons", []),
					"aggregated_reasons": res.get("aggregated_reasons", []),
					"context": context or {},
				}

		correlation_engine = _CorrAdapter()

	if explainability is None:
		from explainability.explainability import ExplainabilityEngine as _ExplainImpl

		class _ExplainAdapter:
			"""Adapter normalizing explainability output to pipeline response contracts."""

			def __init__(self):
				"""Create and hold the underlying explainability engine."""
				self._impl = _ExplainImpl()

			def format_response(self, corr_payload):
				"""Build the final pipeline response from correlation payload data."""
				# Use explainability output for user messaging, then merge with pipeline fields.
				generated = self._impl.generate_explanation({
					"transaction_id": corr_payload.get("transaction_id"),
					"action": corr_payload.get("action"),
					"final_score": corr_payload.get("final_score"),
					"aggregated_reasons": corr_payload.get("aggregated_reasons"),
					"context": corr_payload.get("context", {}),
				})
				return {
					"transaction_id": generated["transaction_id"],
					"action": corr_payload.get("action"),
					"final_score": corr_payload.get("final_score"),
					"override_triggered": corr_payload.get("override_triggered", False),
					"aggregated_reasons": corr_payload.get("aggregated_reasons", []),
					"user_intervention": generated["user_intervention"],
				}

			def generate_direct_response(self, transaction_id, fp_verdict):
				"""Build a direct response for fast-path bypass decisions."""
				# ``fp_verdict`` may be a dict from fast-path; normalize to action/reason.
				if isinstance(fp_verdict, dict):
					action = fp_verdict.get("verdict")
					reason = fp_verdict.get("reason_code")
				else:
					action = fp_verdict
					reason = None

				final_score = 0.0 if action == "ALLOW" else (1.0 if action == "BLOCK" else 0.5)
				generated = self._impl.generate_explanation({
					"transaction_id": transaction_id,
					"action": action,
					"final_score": final_score,
					"aggregated_reasons": [reason] if reason else [],
					"context": {},
				})
				return {
					"transaction_id": transaction_id,
					"action": action,
					"final_score": final_score,
					"override_triggered": action == "BLOCK",
					"aggregated_reasons": [reason] if reason else [],
					"user_intervention": generated["user_intervention"],
				}

		explainability = _ExplainAdapter()

	return FraudDetectionPipeline(fast_path, domain_analyzer, transaction_analyzer, correlation_engine, explainability)
