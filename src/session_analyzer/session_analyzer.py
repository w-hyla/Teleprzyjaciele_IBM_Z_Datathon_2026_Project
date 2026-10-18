"""Session-level anomaly detection utilities.

This module provides a lightweight session analyzer that combines a small
ONNX-based flow anomaly model with a simple LRU baseline store to detect
session hijack signals (JA3/ASN shifts). The implementation is intentionally
small and dependency-light to keep it suitable for hackathon demos and
constrained environments (e.g. LinuxONE).
"""

import collections
import logging
from typing import Tuple

import numpy as np
import onnxruntime as ort

from src.contracts import SessionContext, SessionResult


logger = logging.getLogger("pipeline.operational")


class SessionAnalyzer:
    """Analyze session telemetry and produce a session risk summary.

    The analyzer maintains a small LRU cache of session baselines (JA3 hash,
    ASN, IP) to detect changes indicative of hijacking or middleman attacks.

    Args:
        model_path: Path to the ONNX model used for flow anomaly scoring.
        max_active_sessions: Maximum number of session baselines to retain
            (older entries are evicted in LRU order).
    """

    def __init__(self, model_path: str = "models/session_anomaly.onnx", max_active_sessions: int = 100000):
        # Create an ONNX inference session for small flow-anomaly model.
        # Keep errors surfaced to the caller during instantiation.
        self.session = ort.InferenceSession(model_path)

        # LRU store to keep memory bounded in long-running demos.
        self.max_sessions = max_active_sessions
        self._baselines = collections.OrderedDict()

    def _get_or_update_baseline(
        self, session_id: str, current_ja3: str, current_ip: str, current_asn: int
    ) -> Tuple[bool, bool]:
        """Check and update the baseline fingerprint for a session.

        Returns a pair (ja3_shifted, asn_shifted). If the session is new the
        baseline is recorded and (False, False) is returned.
        """

        if not session_id:
            # Missing session identifier -> cannot compare baselines.
            return False, False

        if session_id in self._baselines:
            baseline = self._baselines[session_id]
            # Move to end to mark as recently used (LRU behavior).
            self._baselines.move_to_end(session_id)

            ja3_shifted = baseline["ja3_hash"] != current_ja3
            asn_shifted = baseline["asn"] != current_asn
            return ja3_shifted, asn_shifted

        # New session: register baseline and evict oldest if over the limit.
        self._baselines[session_id] = {
            "ja3_hash": current_ja3,
            "ip_address": current_ip,
            "asn": current_asn,
        }
        if len(self._baselines) > self.max_sessions:
            self._baselines.popitem(last=False)
        return False, False

    async def analyze(self, session_context: SessionContext) -> SessionResult:
        """Compute a session risk summary from telemetry.

        Steps:
        1. Check for JA3/ASN shifts against a cached baseline.
        2. Run a tiny ONNX flow-anomaly model to score netflow telemetry.
        3. Synthesize session risk and reason codes.

        The function is intentionally robust: ONNX failures degrade to a
        conservative, fail-open score to avoid blocking upstream pipelines.
        """

        session_id = session_context.get("session_id", "")
        ja3_hash = session_context.get("ja3_hash", "")
        ip_address = session_context.get("ip_address", "")
        asn = session_context.get("asn", 0)

        # 1) Baseline identity check (JA3/ASN shifts)
        ja3_shift, asn_shift = self._get_or_update_baseline(session_id, ja3_hash, ip_address, asn)

        # 2) Prepare flow telemetry vector for ONNX model
        flow_vector = np.array(
            [
                [
                    session_context.get("flow_duration", 0.0),
                    session_context.get("flow_bytes_per_sec", 0.0),
                    session_context.get("packet_rate", 0.0),
                ]
            ],
            dtype=np.float32,
        )

        # ONNX inference guarded to keep pipeline available on model failures.
        try:
            onnx_preds = self.session.run(None, {self.session.get_inputs()[0].name: flow_vector})
            # Model output indexing depends on model shape; keep as float.
            flow_anomaly_score = float(onnx_preds[0][0][1])
        except Exception as exc:  # pragma: no cover - operational fallback
            logger.warning("Session ONNX inference failure: %s", exc)
            flow_anomaly_score = 0.50

        # 3) Synthesize session risk and reasons
        session_risk = flow_anomaly_score
        reason_codes = []

        # Penalize when identity shifts are detected (possible hijack).
        if ja3_shift or asn_shift:
            session_risk = max(session_risk, 0.85)
            reason_codes.append("SESSION_HIJACK_JA3_SHIFT")

        if flow_anomaly_score > 0.75:
            reason_codes.append("FLOW_ANOMALY_HIGH")

        return {
            "session_risk": round(session_risk, 2),
            "reason_codes": reason_codes,
            "details": {
                "ja3_shift_detected": ja3_shift,
                "asn_shift_detected": asn_shift,
                "onnx_flow_anomaly_score": round(flow_anomaly_score, 2),
                "baseline_ip_match": not asn_shift,
            },
        }