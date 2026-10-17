# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project state

Hackathon project (IBM Z Datathon 2026, team Teleprzyjaciele): a hybrid fraud + phishing detection pipeline for bank transfers that protects elderly users. Target platform: **LinuxONE / s390x, Python 3.11+, latency budget < 25 ms per transaction**.

Implemented so far: `src/fast_path.py` and `src/domain_analyzer.py`, with shared parsing and data loaders in `src/domain_utils.py`. A teammate owns `transaction_analyzer`. `correlation_engine`, `explainability`, the orchestrator, `models/`, `notebooks/` and `demo/` don't exist yet. The code uses only the standard library (a deliberate "nothing fancy" choice), so `requirements` (no `.txt` extension) is still empty.

## Commands

Run these from the repo root. `src` is imported as a package (`from src.fast_path import check`).

```sh
python -m unittest discover -s tests -t .              # all tests
python -m unittest tests.test_domain_analyzer          # one file
python -m unittest tests.test_fast_path.FastPathTest.test_phishtank_host_is_blocked  # one test
```

The data loaders use `lru_cache`. The first call reads Tranco and PhishTank (~0.3 s), and later calls cost about 1 ms for `analyze` and a few µs for `check`.

The specs live in `architecture/` and are written in Polish. Treat them as the source of truth for I/O contracts, thresholds, and reason codes:
- `architecture/pipeline_integration_contract.md`: global data flow, the `PipelineRequest`/`PipelineResponse` schemas, and orchestration rules
- `architecture/modules/*.md`: per-module I/O contract, Mermaid flow, algorithm, and reason codes

`docs/Abstract&mapaMysli ibm datathon.pdf` is the submitted abstract (English) plus a Polish threat → signal → tool mind map. It is the source for the evaluation plan, not for contracts:
- Ablation study: domain-only vs transaction-only vs hybrid correlation, measured by PR-AUC, recall, FPR, and end-to-end latency.
- Use time-based splits (PaySim `step`) to avoid leakage. Elder-fraud scenarios that pair a lookalike/phishing domain with an account-drain transfer are synthesized, because no dataset links the two layers.
- Out of scope for now: Session Analyzer (JA3/JA4, IP/ASN jumps), DNS tunneling, and scam NLP. The mind map marks these as roadmap or optional.

## Pipeline architecture

Five modules run in three phases:

1. **`fast_path`**: whitelist/blacklist triage. Whitelist is `trusted_banks` (Polish banks, BLIK, PayU). Blacklist is a hash lookup against `data/phishtank.csv`. A whitelisted domain with `amount <= 1.5 * history_avg_amount` gets `ALLOW`/`KNOWN_BENIGN` and a blacklisted domain gets `BLOCK`/`BLACKLISTED_PHISH`, both with `bypass_pipeline=True`. Everything else gets `DEEP_CHECK` with `UNUSUAL_AMOUNT` (whitelisted, but the amount is too high) or `UNKNOWN_DOMAIN`.
2. **`domain_analyzer`** and **`transaction_analyzer`** run **in parallel** (`asyncio.gather` or threads), only when `bypass_pipeline == False`.
   - domain runs three checks in sequence. Each one raises the risk and none of them stop the chain:
     - Homoglyphs: an `xn--` prefix, mixed scripts (UTS #39, `data/homoglyphs.csv`), or a match after normalizing `rn→m` and `cl→d`. Gives `HOMOGLYPH_DETECTED`, risk 0.95.
     - Typosquatting: Levenshtein distance to the brand list (see "Decisions already made" below).
     - DGA: Shannon entropy H > 3.8, or a consonant/vowel ratio > 4.0. Gives `DGA_HIGH_ENTROPY`, risk 0.75.
     
     Output is `domain_risk = max(component risks)`, with a floor of 0.05 for unknown domains.
   - transaction: anything other than `TRANSFER`/`CASH_OUT` short-circuits to 0.05 with `LOW_RISK_PAYMENT`. In `data/paysim_downsized.csv`, every fraud is one of those two types. For those two types, the analyzer flags zero-balance drain (`R_drain = amount / (oldbalanceOrg + ε) >= 0.85`) and a mule destination (`oldbalanceDest == newbalanceDest == 0`). It then runs ONNX on the 7-feature vector `[type_enc, log1p(amount), oldbalanceOrg, newbalanceOrig, oldbalanceDest, newbalanceDest, R_drain]` (`models/fraud_detect.onnx` via `onnxruntime`). Training must use the same feature order. An `onnx_score >= 0.70` adds `ONNX_ANOMALY_HIGH`. Output is `transaction_risk = min(1, max(onnx_score, is_drain * 0.85))`.
3. **`correlation_engine`** fuses the two scores (domain 45%, tx 55%, with a critical override plus a `CROSS_LAYER_SYNERGY_PENALTY` rule) into `final_score` and `action ∈ {ALLOW, STEP_UP, DELAY, BLOCK}`. **`explainability`** turns the result into senior-friendly Polish UI text plus an audit line.

Cross-cutting rules from the integration contract:
- **Short-circuit:** when `fast_path` bypasses, modules 2–4 do not run, and its verdict goes straight to `explainability`.
- **Fail-safe:** if an analyzer fails (for example, the ONNX model doesn't load), the system does not go down. Fall back to a safe value (`tx_risk = 0.50` + `FALLBACK_TRIGGERED`, or fail-open).
- Every module returns a normalized risk in `[0.0, 1.0]` plus `reason_codes: list[str]`. The codes are the contract with `explainability`. It picks **one** primary reason using a fixed priority: homoglyph/typosquat > `ACCOUNT_DRAIN_ZERO_BALANCE` > `MULE_DEST_ANOMALY` > `CROSS_LAYER_SYNERGY_PENALTY` > `DGA_HIGH_ENTROPY`/`ONNX_ANOMALY_HIGH`.
- User-facing text must avoid technical jargon ("entropia", "homoglif", "ONNX", "Punycode"). A `DELAY` action uses the 15-minute de-escalation message.
- Audit format: `[AUDIT] SCORE={final_score:.2f} | ACTION={action} | REASONS={aggregated_reasons} | TS={timestamp}`

### Known gaps and inconsistencies in the specs

Resolve these with the user instead of guessing:
- `correlation_engine` has no module spec in `architecture/modules/`. Only its 45/55 weights appear, in the integration contract's responsibility matrix. Nothing defines the `final_score` → action thresholds, the critical-override trigger, or the synergy rule. `PipelineResponse.override_triggered` depends on them.
- fast_path: its output has `reason_code: str | None` (singular), while every other module returns `reason_codes: list[str]`. The code keeps the singular field, as the spec has it.
- transaction_analyzer: `MULE_DEST_ANOMALY` is only a flag and does not enter the `transaction_risk` formula. `HIGH_RISK_TX_TYPE` is defined but never emitted.
- transaction_analyzer: the flowchart's drain condition is `newbalanceOrig == 0`, but the text says `newbalanceOrig <= 0.05 * oldbalanceOrg`. The contract example (15000 → 500) is a drain only under the text version.
- explainability: the message dictionary covers only 4 codes (homoglyph, typosquat, drain, synergy). It has no text for `MULE_DEST_ANOMALY`, `DGA_HIGH_ENTROPY`, `ONNX_ANOMALY_HIGH`, `FALLBACK_TRIGGERED`, or the fast_path `BLOCK`/`BLACKLISTED_PHISH` path. The action → `ui_severity` mapping is also unspecified.
- Audit format: explainability uses `[AUDIT] SCORE=… | ACTION=… | REASONS=… | TS=…`. The contract example uses `[AUDIT] ID=… SCORE=… ACTION=… REASONS=…`, with an ID, no pipes, no TS, and abbreviated codes.
- Transaction model type: the abstract promises LSTM/GRU over sequential transaction history, but `transaction_analyzer.md` defines one 7-feature vector per transaction (`type_enc, log1p(amount), balances…, R_drain`) and calls the model "sekwencyjny/tabelaryczny". The ONNX input shape depends on which one you pick.
- Field names differ between documents. The module spec uses `transaction_risk` and the contract uses `tx_risk`. Explainability outputs `ui_severity`/`user_title`/`user_message`/`recommended_action`/`audit_summary`, but `PipelineResponse.user_intervention` uses `severity`/`title`/`message`/`action_prompt`.

### Decisions already made (fast_path / domain_analyzer)

- `TRUSTED_DOMAINS` in `src/domain_utils.py` is a hand-written list of Polish banks, payment services, Allegro, InPost and OLX. It serves as both the fast_path whitelist and the default `target_brands`. Tranco is not a brand list: Levenshtein against 1M domains in pure Python would blow the latency budget.
- Tranco is used for two filters only:
  - PhishTank hosts whose registrable domain is in the top 10k are dropped from the blacklist (otherwise `sites.google.com` and `bit.ly` would get BLOCK);
  - the SLD of a domain in the top 100k is never flagged as a typosquat.
- Typosquatting uses the text version: d=1 → 0.90, d=2 → 0.70. Subdomain labels and hyphen-separated parts are checked too, and an exact brand match there (d=0) → 0.90. With this, the contract example `mbank.pl.weryfikacja-konta.top` gets the code.
- False-positive guards:
  - brands under 4 characters (`ing`, `olx`, `sgb`) match exactly only;
  - in subdomains and hyphen-separated parts, brands under 7 characters must match exactly (`bank` ≠ `mbank`);
  - the same SLD with a different suffix (`ing.com`) is not flagged.
- Known simplifications:
  - every IDN (`xn--` or non-ASCII) is flagged `HOMOGLYPH_DETECTED`, as the spec says, including legitimate Polish domains;
  - `MULTI_PART_SUFFIXES` is a short list, not the Public Suffix List.
- The spec's example `xn--mbnk-81a.pl` is not valid IDNA (it does not round-trip). The analyzer decodes it as raw punycode.

## Data (`data/`)

- `paysim_downsized.csv`: PaySim columns `step,type,amount,nameOrig,oldbalanceOrg,newbalanceOrig,nameDest,oldbalanceDest,newbalanceDest,isFraud,isFlaggedFraud`. Note PaySim's inconsistent spelling: `oldbalanceOrg` vs `newbalanceOrig`. Keep it as-is, because the contracts use it.
- `phishtank.csv`: `phish_id,url,...,target`. These are full URLs, so extract the domain before hashing or lookup.
- `tranco_top_1m.csv`: headerless `rank,domain`, with CRLF line endings
- `homoglyphs.csv`: `target_char,target_name,homoglyph_char,homoglyph_hex,homoglyph_script`
