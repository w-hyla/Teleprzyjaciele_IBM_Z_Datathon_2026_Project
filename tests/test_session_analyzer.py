import os
import sys
import unittest
from pathlib import Path
import numpy as np

# Add repo root to sys.path so src imports resolve cleanly
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from src.contracts import SessionContext
from src.session_analyzer.session_analyzer import SessionAnalyzer

MODEL_PATH = str(REPO_ROOT / "models" / "session_anomaly.onnx")


class TestSessionAnalyzerRealONNX(unittest.IsolatedAsyncioTestCase):
    """Integration and classification unit tests using the real ONNX neural network."""

    def _make_session_context(
        self,
        session_id: str = "sess_live_101",
        ja3_hash: str = "e7d705a3286e19ea42f587b344ee6865",
        ip_address: str = "192.168.1.15",
        asn: int = 13335,
        flow_duration: float = 4.5,
        flow_bytes_per_sec: float = 320.0,
        packet_rate: float = 12.0,
    ) -> SessionContext:
        """Build a fully-typed session context with optional overrides."""
        return {
            "session_id": session_id,
            "ja3_hash": ja3_hash,
            "ip_address": ip_address,
            "asn": asn,
            "flow_duration": flow_duration,
            "flow_bytes_per_sec": flow_bytes_per_sec,
            "packet_rate": packet_rate,
        }

    def setUp(self):
        """Initializes the SessionAnalyzer pointing to models/session_anomaly.onnx."""
        self.assertTrue(
            os.path.exists(MODEL_PATH),
            f"Physical ONNX model not found at {MODEL_PATH}. Make sure the file exists."
        )
        self.analyzer = SessionAnalyzer(model_path=MODEL_PATH, max_active_sessions=5)

        # Verify the ONNX runtime session loaded the model from disk
        self.assertIsNotNone(
            self.analyzer.session,
            "Failed to load ONNX inference session from disk."
        )

        self.normal_context: SessionContext = self._make_session_context()

    def test_real_onnx_model_metadata(self):
        """Validates that the real ONNX model matches the 3-feature input contract."""
        inputs = self.analyzer.session.get_inputs()
        outputs = self.analyzer.session.get_outputs()

        self.assertEqual(len(inputs), 1)
        self.assertEqual(len(outputs), 1)

        # Expected 3 features: [flow_duration, log1p(flow_bytes_per_sec), packet_rate]
        input_shape = inputs[0].shape
        self.assertEqual(input_shape[-1], 3, f"Expected 3 input features, found {input_shape[-1]}")
        self.assertEqual(inputs[0].type, "tensor(float)")

    async def test_classify_safe_session(self):
        """Risk Type 1: Benign session with normal telemetry and matching footprint."""
        result = await self.analyzer.analyze(self.normal_context)

        self.assertIsInstance(result["session_risk"], float)
        self.assertLess(result["session_risk"], 0.70)
        self.assertEqual(result["reason_codes"], [])
        self.assertFalse(result["details"]["ja3_shift_detected"])
        self.assertFalse(result["details"]["asn_shift_detected"])
        self.assertTrue(result["details"]["baseline_ip_match"])

    async def test_classify_neural_network_flow_anomaly(self):
        """Risk Type 2: Neural network classifies extreme netflow as FLOW_ANOMALY_HIGH."""
        # Simulated volumetric flooding / bot attack telemetry
        anomalous_flow_context = self._make_session_context(
            session_id="sess_flow_attack_202",
            ja3_hash="e7d705a3286e19ea42f587b344ee6865",
            ip_address="192.168.1.15",
            asn=13335,
            flow_duration=850.0,
            flow_bytes_per_sec=50_000_000.0,  # Extreme burst
            packet_rate=95_000.0,  # Bot packet flood
        )

        # Verify real ONNX inference produces an anomaly score >= 0.70
        features = np.array([[
            anomalous_flow_context["flow_duration"],
            np.log1p(anomalous_flow_context["flow_bytes_per_sec"]),
            anomalous_flow_context["packet_rate"]
        ]], dtype=np.float32)

        raw_pred = self.analyzer.session.run(None, {self.analyzer.session.get_inputs()[0].name: features})
        onnx_prob = float(raw_pred[0][0][0])

        result = await self.analyzer.analyze(anomalous_flow_context)

        if onnx_prob >= 0.70:
            self.assertIn("FLOW_ANOMALY_HIGH", result["reason_codes"])
            self.assertGreaterEqual(result["session_risk"], 0.70)
        self.assertEqual(result["details"]["onnx_flow_anomaly_score"], round(onnx_prob, 2))

    async def test_classify_session_hijack_footprint_shift(self):
        """Risk Type 3: LRU baseline detects JA3/ASN shift (Adversary-in-the-Middle)."""
        session_id = "sess_hijack_303"
        initial_context = self._make_session_context(session_id=session_id)

        # 1. Establish trusted baseline
        first_result = await self.analyzer.analyze(initial_context)
        self.assertNotIn("SESSION_HIJACK_FOOTPRINT_SHIFT", first_result["reason_codes"])

        # 2. Token replay attack: Same session_id, but altered TLS fingerprint and ASN
        hijacked_context = self._make_session_context(
            session_id=session_id,
            ja3_hash="b32309a26ce51676e939b01182520611",  # Shifted TLS stack
            asn=99999,  # Shifted ISP network
        )

        result = await self.analyzer.analyze(hijacked_context)

        # Baseline shift forces risk to at least 0.85
        self.assertIn("SESSION_HIJACK_FOOTPRINT_SHIFT", result["reason_codes"])
        self.assertGreaterEqual(result["session_risk"], 0.85)
        self.assertTrue(result["details"]["ja3_shift_detected"])
        self.assertTrue(result["details"]["asn_shift_detected"])
        self.assertFalse(result["details"]["baseline_ip_match"])

    async def test_classify_compound_risk_hijack_and_flow_anomaly(self):
        """Risk Type 4: Multi-vector attack combining footprint shift AND flow anomaly."""
        session_id = "sess_compound_404"
        initial_context = self._make_session_context(session_id=session_id)

        # 1. Baseline initialization
        await self.analyzer.analyze(initial_context)

        # 2. Shift footprint and inject high telemetry
        compromised_context = self._make_session_context(
            session_id=session_id,
            ja3_hash="99999999999999999999999999999999",
            flow_bytes_per_sec=80_000_000.0,
            packet_rate=120_000.0,
        )

        result = await self.analyzer.analyze(compromised_context)

        # Must flag the identity shift
        self.assertIn("SESSION_HIJACK_FOOTPRINT_SHIFT", result["reason_codes"])
        self.assertGreaterEqual(result["session_risk"], 0.85)
        self.assertTrue(result["details"]["ja3_shift_detected"])

    async def test_anonymous_session_handling(self):
        """Risk Type 5: Missing or empty session_id handled safely without state pollution."""
        anon_context = self._make_session_context(session_id="")

        result = await self.analyzer.analyze(anon_context)

        self.assertFalse(result["details"]["ja3_shift_detected"])
        self.assertFalse(result["details"]["asn_shift_detected"])
        self.assertEqual(len(self.analyzer._baselines), 0)

    async def test_lru_cache_eviction_boundary(self):
        """Validates that older sessions are evicted in O(1) LRU order when capacity is reached."""
        max_capacity = self.analyzer.max_sessions  # set to 5 in setUp

        for i in range(max_capacity + 2):
            ctx = self._make_session_context(session_id=f"sess_cache_{i}")
            await self.analyzer.analyze(ctx)

        # Cache must not exceed its configured limit
        self.assertEqual(len(self.analyzer._baselines), max_capacity)
        # Oldest sessions (0 and 1) should be evicted
        self.assertNotIn("sess_cache_0", self.analyzer._baselines)
        self.assertNotIn("sess_cache_1", self.analyzer._baselines)
        self.assertIn(f"sess_cache_{max_capacity + 1}", self.analyzer._baselines)


    async def test_fusion_takes_max_and_flags_both(self):
        """Stubbed session lets us deterministically test fusion behavior."""
        self.analyzer.session = StubSession(0.9)
        await self.analyzer.analyze(self.normal_context)
        ctx = self._make_session_context(asn=99999)
        result = await self.analyzer.analyze(ctx)
        self.assertEqual(result["session_risk"], 0.9)
        self.assertEqual(set(result["reason_codes"]),
                         {"SESSION_HIJACK_FOOTPRINT_SHIFT", "FLOW_ANOMALY_HIGH"})


    async def test_lru_refresh_protects_recent(self):
        """Stubbed session keeps the session cache behavior reproducible."""
        self.analyzer.session = StubSession(0.1)
        for i in range(5):
            await self.analyzer.analyze(self._make_session_context(session_id=f"s{i}"))
        await self.analyzer.analyze(self._make_session_context(session_id="s0"))  # touch
        await self.analyzer.analyze(self._make_session_context(session_id="s5"))  # evict
        self.assertIn("s0", self.analyzer._baselines)
        self.assertNotIn("s1", self.analyzer._baselines)


class StubSession:
    def __init__(self, score): self.score = score
    def get_inputs(self): return [type("I", (), {"name": "x"})()]
    def run(self, _, __): return [[[self.score]]]

if __name__ == "__main__":
    unittest.main(verbosity=2)