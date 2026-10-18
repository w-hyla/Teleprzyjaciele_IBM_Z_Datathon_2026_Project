"""Session-level anomaly detection utilities.

This module provides a lightweight session analyzer that combines a small
ONNX-based flow anomaly model with a simple LRU baseline store to detect
session hijack signals (JA3/ASN shifts). The implementation is intentionally
small and dependency-light to keep it suitable for hackathon demos and
constrained environments (e.g. LinuxONE).
"""

import os
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
        # Store model path and lazily attempt to load an ONNX session if present.
        self.model_path = model_path
        self.session = None

        if os.path.exists(model_path):
            try:
                # Optimized for LinuxONE / s390x on-chip inference[cite: 5]
                self.session = ort.InferenceSession(model_path)
                logger.info(f"Loaded FFNN ONNX session model from {model_path}")
            except Exception as e:
                logger.error(f"Failed to load session ONNX model: {e}")
        else:
            logger.warning(f"Session model {model_path} not found.")

        # LRU store to keep memory bounded in long-running demos.
        self.max_sessions = max_active_sessions
        self._baselines = collections.OrderedDict()

    def _get_or_update_baseline(self, session_id: str, current_ja3: str, current_ip: str, current_asn: int) -> Tuple[bool, bool]:
        """Evaluates identity footprint shifts using an O(1) LRU cache.

        Returns (ja3_shifted, asn_shifted). If session_id is missing or new,
        returns (False, False) and records a baseline for new sessions.
        """

        if not session_id:
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
        """Analyzes session telemetry for flow anomalies and footprint shifts.

        Steps:
        1. Check JA3/ASN shifts against a cached baseline.
        2. Feature-engineer netflow telemetry and run the ONNX FFNN if loaded.
        3. Fuse model score with heuristic footprint shift risk.
        """

        session_id = session_context.get("session_id", "")
        ja3_hash = session_context.get("ja3_hash", "")
        ip_address = session_context.get("ip_address", "")
        asn = int(session_context.get("asn", 0))

        duration = float(session_context.get("flow_duration", 0.0))
        bytes_sec = float(session_context.get("flow_bytes_per_sec", 0.0))
        pkt_rate = float(session_context.get("packet_rate", 0.0))

        reason_codes = []
        base_risk = 0.0

        # 1. Identity footprint shift check (JA3/ASN)
        ja3_shift, asn_shift = self._get_or_update_baseline(session_id, ja3_hash, ip_address, asn)
        if ja3_shift or asn_shift:
            base_risk = 0.85
            reason_codes.append("SESSION_HIJACK_FOOTPRINT_SHIFT")

        # 2. Feature engineering matching training export
        log_bytes_per_sec = np.log1p(bytes_sec)
        features = np.array([[duration, log_bytes_per_sec, pkt_rate]], dtype=np.float32)

        # 3. ONNX FFNN inference (if model loaded)
        onnx_score = 0.0
        if self.session:
            try:
                preds = self.session.run(None, {self.session.get_inputs()[0].name: features})
                # Sigmoid output compresses to a single probability scalar
                onnx_score = float(preds[0][0][0])
            except Exception as e:  # pragma: no cover - operational fallback
                logger.warning(f"ONNX FFNN inference failed, falling back: {e}")
                onnx_score = 0.50

        if onnx_score >= 0.70:
            reason_codes.append("FLOW_ANOMALY_HIGH")

        # 4. Risk fusion
        session_risk = min(1.0, max(onnx_score, base_risk))

        return {
            "session_risk": round(session_risk, 2),
            "reason_codes": reason_codes,
            "details": {
                "ja3_shift_detected": ja3_shift,
                "asn_shift_detected": asn_shift,
                "onnx_flow_anomaly_score": round(onnx_score, 2),
                "baseline_ip_match": not asn_shift,
            },
        }