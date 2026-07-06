# USDT swap — staging runbook (prod-key + render steps)

**Date:** 2026-06-15
**Context:** C1 of the WDK audit — the `× Tether WDK` page should lead with **USDT, not USDC**. Instrument is the message on a Tether-facing page.

## Done (self-verified, local, unpushed)

| Change | Where | Evidence |
|---|---|---|
| Public "verify it yourself" demo → USDT | `wdk-op-policy/examples/verify-yourself.mjs` + new `cred-wdk-usdt` fixture (`test/fixtures/gen.mjs`, `consts.mjs`) | `npm run verify` prints `transfer 50/150 USDT`, `op-violation` via real WDK PR #55 engine |
| Conformance core left on USDC (internal only) | `test/run.mjs` (untouched) | `npm test` → **26 passed, 0 failed** |
| Page prose + img alt → USDT | `observerprotocol-website/wdk.html` (TRACK 1/2, hero) | grep shows `USDT`, no `USDC` in demo prose |
| PEC framing fixed (A2) | `wdk.html` meta + body | "OP's own evaluation of the same mandate" replaces "record of every decision" |
| NEURA citation added (C2) | `wdk.html` | links tether.io NEURA Series-C release |
| Endpoint-free PEC verify via canonical libs + CI (A3) | `observerprotocol-website/tools/pec-verify/` + `.github/workflows/pec-verify.yml` | `npm run verify:local` → `@digitalbazaar Data Integrity verify -> true` |

## Blocked on prod signing keys / render — DO BEFORE PUBLISH

These artifacts are **prod-signed** (or rendered), so they cannot be regenerated without the key material / a render step. Until they are done, **do not publish the page in a half-USDT state.**

### 1. Hosted PEC → USDT, re-sign with `#key-3`
- File: `observerprotocol-website/credentials/maxi-0001-wdk-demo-pec.json` (currently USDC, signed `did:web:observerprotocol.org#key-3`).
- The PEC is the **output of the policy engine** evaluating the USDT mandate. Regenerate it through the live policy-engine signing path (op-vps sidecar, `#key-3`), with the proposal/`evaluatedAgainst` denominated in USDT.
- After deploy, the A3 CI check (`tools/pec-verify`) verifies the new PEC automatically — no code change needed.

### 2. Mandate asset → USDT, re-sign with `#key-5`
- File: `wdk-op-policy/demo/assets/maxi-payment-delegation.json` (USDC, signed `#key-5`).
- Unsigned USDT body prepared: `demo/assets/maxi-payment-delegation.usdt-unsigned.json`. Re-sign it with `#key-5` (eddsa-jcs-2022), drop the `__staging_note` key, and replace the live asset.

### 3. `social-demo.mjs` → USDT (depends on #2)
- File: `wdk-op-policy/demo/social-demo.mjs` (uses the `#key-5` asset above + `USDC_CONTRACT`/`USDC`).
- It cannot be half-swapped: the asset's mandate currency must match the proposal, or the engine denies on currency mismatch. Once the asset (#2) is USDT, switch `USDC_CONTRACT`/`USDC` → `USDT_CONTRACT`/`USDT` (already in `consts.mjs`) and the `USDC` labels to `USDT`.

### 4. Screenshot re-render
- File: `observerprotocol-website/wdk-1-demo-terminal.png` (shows USDC).
- Re-render from the new USDT output, captured verbatim at `wdk-op-policy/demo/assets/wdk-1-demo-terminal.usdt.txt`. The `wdk.html` `alt` text is already updated to USDT.

## Why conformance stayed USDC
Per the standing rule, "never lead with USDC" governs the **public demo and copy**, not internal conformance fixtures. The 26-test conformance suite exercises the EVM resolver internals and keeps USDC to avoid a large, risky diff to the audited core (A1/A3 soundness). Only the public-facing path moved to USDT.
