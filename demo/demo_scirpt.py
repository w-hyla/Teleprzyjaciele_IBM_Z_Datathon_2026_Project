#!/usr/bin/env python3
"""Demo runner that composes the pipeline and runs example payloads.

This script uses the package-level factory `create_pipeline()` to build a
FraudDetectionPipeline with sensible defaults and runs a few example
transactions. It purposely manipulates sys.path so you can run it from the
repository root:

    python demo/demo_scirpt.py

"""
from pathlib import Path
import sys
import asyncio
import logging
import time

# Ensure repository root is on sys.path so `src` can be imported as a package.
REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from src import create_pipeline


logger = logging.getLogger("pipeline")


def payload(domain, amount=100.0, history_avg_amount=350.0, transaction_id="tx_demo_0001", session_override=None):
    old_balance = 15000.0

    # Standard trusted baseline session (Layer 2)
    session_context = {
        "session_id": "sess_user_001",
        "ja3_hash": "771,4865-4866-4867,0-11-10",
        "ip_address": "192.168.1.50",
        "asn": 12345,
        "flow_duration": 15.0,
        "flow_bytes_per_sec": 150.0,
        "packet_rate": 5.0,
    }

    if session_override:
        session_context.update(session_override)

    return {
        "transaction_id": transaction_id,
        "domain": domain,
        "transaction": {
            "type": "TRANSFER",
            "amount": amount,
            "oldbalanceOrg": old_balance,
            "newbalanceOrig": old_balance - amount,
            "oldbalanceDest": 0.0,
            "newbalanceDest": 0.0,
        },
        "user_context": {"history_avg_amount": history_avg_amount},
        "session_context": session_context,  # NEW: Injected into all requests
    }


def allow_payload():
    """Safe transaction from a known device and domain."""
    return payload("mbank.pl", amount=100.0, history_avg_amount=350.0, transaction_id="tx_allow_0001")


def block_payload():
    """Phishing attempt with an obvious bad domain."""
    return payload("http://allegro.pl.showitems.ca/oferta", transaction_id="tx_block_0001")


def aitm_hijack_payload():
    """
    Theme 2 (AI Secured) Zero-Trust Scenario:
    The attacker has stolen a valid session token and is using the legitimate bank website,
    but their network footprint (JA3/ASN) has shifted and flow rates indicate automation.
    """
    hijacked_session = {
        "ja3_hash": "771,4865-4866,0-11",  # Shifted TLS Fingerprint
        "asn": 54321,  # Traffic coming from a new ISP
        "flow_duration": 0.5,  # Micro-burst implies bot tooling
        "packet_rate": 350.0,  # Unusually high packet rate
    }
    # An unusual amount (6000 vs 350 avg) combined with a hijacked session triggers the Cross-Layer Synergy Penalty
    return payload("mbank.pl", amount=6000.0, transaction_id="tx_hijack_0001", session_override=hijacked_session)


def _payload_summary(payload_data):
    """Build a compact summary for log messages."""
    tx = payload_data["transaction"]
    session = payload_data.get("session_context", {})
    return {
        "transaction_id": payload_data.get("transaction_id"),
        "domain": payload_data.get("domain"),
        "amount": tx.get("amount"),
        "history_avg_amount": payload_data.get("user_context", {}).get("history_avg_amount"),
        "ja3_hash": session.get("ja3_hash"),
        "asn": session.get("asn"),
        "flow_duration": session.get("flow_duration"),
        "packet_rate": session.get("packet_rate"),
    }


async def main():
    logger.info("[DEMO] Starting demo run and building pipeline")
    print("Building pipeline (this may take a moment while ONNX models initialize on LinuxONE)...")
    build_started = time.perf_counter()
    pipeline = create_pipeline()
    logger.info("[DEMO] Pipeline initialized in %.2fs", time.perf_counter() - build_started)

    examples = [allow_payload(), block_payload(), aitm_hijack_payload()]
    logger.info("[DEMO] Prepared %d demo payloads", len(examples))

    for idx, p in enumerate(examples, start=1):
        summary = _payload_summary(p)
        print("\n" + "=" * 60)
        print(f"INPUT payload [{p['transaction_id']}]:\n", p)
        logger.info(
            "[DEMO] Processing payload %d/%d: tx_id=%s domain=%s amount=%.2f history_avg=%.2f",
            idx,
            len(examples),
            summary["transaction_id"],
            summary["domain"],
            summary["amount"],
            summary["history_avg_amount"],
        )
        logger.info(
            "[DEMO] Session context: ja3=%s asn=%s flow_duration=%s packet_rate=%s",
            summary["ja3_hash"],
            summary["asn"],
            summary["flow_duration"],
            summary["packet_rate"],
        )
        tx_started = time.perf_counter()
        try:
            result = await pipeline.process_transaction(p)
        except Exception as e:
            print("Pipeline execution failed:", e)
            logger.exception("[DEMO] Pipeline execution failed for %s", p["transaction_id"])
            continue
        elapsed = time.perf_counter() - tx_started
        logger.info(
            "[DEMO] Completed %s in %.2fs -> action=%s final_score=%s reasons=%s",
            p["transaction_id"],
            elapsed,
            result.get("action"),
            result.get("final_score"),
            result.get("aggregated_reasons") or result.get("reasons") or [],
        )
        print("\nOUTPUT:\n", result)


if __name__ == "__main__":
    asyncio.run(main())

