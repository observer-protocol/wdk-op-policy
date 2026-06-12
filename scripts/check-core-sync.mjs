#!/usr/bin/env node
// Drift guard: every file in src/core/ must be byte-identical to the same file
// in the sibling ows-op-policy/src/ checkout. The vendored core is
// security-critical and must not diverge between the two engines.
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const coreDir = join(here, '..', 'src', 'core');
const siblingSrc = join(here, '..', '..', 'ows-op-policy', 'src');

if (!existsSync(siblingSrc)) {
  console.warn(`[core-sync] sibling source not found at ${siblingSrc} — SKIPPING (run where ows-op-policy is checked out)`);
  process.exit(0);
}

const drift = [];
for (const f of readdirSync(coreDir)) {
  if (!f.endsWith('.ts')) continue;
  const mine = join(coreDir, f);
  const theirs = join(siblingSrc, f);
  if (!existsSync(theirs)) {
    drift.push(`${f}: present in core/ but missing in ows-op-policy/src/`);
    continue;
  }
  if (readFileSync(mine, 'utf8') !== readFileSync(theirs, 'utf8')) {
    drift.push(`${f}: DIFFERS from ows-op-policy/src/${f}`);
  }
}

if (drift.length > 0) {
  console.error('[core-sync] vendored core has drifted from the source of truth:');
  for (const d of drift) console.error('  - ' + d);
  console.error('Re-vendor from ows-op-policy or reconcile the change in both engines.');
  process.exit(1);
}
console.log('[core-sync] OK — vendored core is byte-identical to ows-op-policy/src/');
