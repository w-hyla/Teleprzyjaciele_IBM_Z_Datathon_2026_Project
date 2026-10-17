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

# Ensure repository root is on sys.path so `src` can be imported as a package.
REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from src import create_pipeline


def payload(domain, amount=100.0, history_avg_amount=350.0, transaction_id="tx_demo_0001"):
    old_balance = 15000.0
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
    }


def contract_payload():
    return {
        "transaction_id": "tx_987213812",
        "domain": "mbank.pl.weryfikacja-konta.top",
        "transaction": {
            "type": "TRANSFER",
            "amount": 14500.00,
            "oldbalanceOrg": 15000.00,
            "newbalanceOrig": 500.00,
            "oldbalanceDest": 0.00,
            "newbalanceDest": 0.00,
        },
        "user_context": {"history_avg_amount": 350.00},
    }


def allow_payload():
    return payload("mbank.pl", amount=100.0, history_avg_amount=350.0, transaction_id="tx_allow_0001")


def block_payload():
    return payload("http://allegro.pl.showitems.ca/oferta", transaction_id="tx_block_0001")


async def main():
    print("Building pipeline (this may take a moment while modules initialize)...")
    pipeline = create_pipeline()

    examples = [allow_payload(), block_payload(), contract_payload()]

    for p in examples:
        print("\n---\nINPUT payload:\n", p)
        try:
            result = await pipeline.process_transaction(p)
        except Exception as e:
            print("Pipeline execution failed:", e)
            continue
        print("OUTPUT:\n", result)


if __name__ == "__main__":
    asyncio.run(main())

