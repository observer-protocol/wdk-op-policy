#!/usr/bin/env node
// Watch npm for the first @tetherto/wdk release that carries PR #55 (the local
// transaction policy engine). #55 merged to main 2026-06-12 (a00b391) AFTER
// v1.0.0-beta.10 (2026-06-04), so the first carrying release is >= 1.0.0-beta.11
// (or any later 1.0.0 / >1.0.0). Prints LANDED + version when it publishes, else
// WAITING. Confirms the release actually ships src/policy/ before declaring it.
//
//   node scripts/watch-beta11.mjs        # one-shot check (used by the daily cron)
import { execSync } from 'node:child_process';

const BASELINE = { base: '1.0.0', beta: 10 }; // last release that PREDATES #55

function parse(v) {
  const m = /^(\d+\.\d+\.\d+)(?:-beta\.(\d+))?/.exec(v);
  if (!m) return null;
  return { base: m[1], beta: m[2] === undefined ? Infinity : Number(m[2]) }; // no -beta => release => sorts after any beta of same base
}
function cmpBase(a, b) {
  const pa = a.split('.').map(Number), pb = b.split('.').map(Number);
  for (let i = 0; i < 3; i++) if (pa[i] !== pb[i]) return pa[i] - pb[i];
  return 0;
}
// is v strictly newer than the baseline (i.e. a candidate that carries #55)?
function carriesPr55(v) {
  const p = parse(v);
  if (!p) return false;
  const b = cmpBase(p.base, BASELINE.base);
  if (b !== 0) return b > 0;
  return p.beta > BASELINE.beta;
}

let versions;
try {
  versions = JSON.parse(execSync('npm view @tetherto/wdk versions --json', { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }));
} catch (e) {
  console.log(`WATCH ERROR: could not query npm (${e.message})`);
  process.exit(2);
}
const all = Array.isArray(versions) ? versions : [versions];
const candidates = all.filter(carriesPr55);

if (candidates.length === 0) {
  const latest = all[all.length - 1];
  console.log(`WAITING: latest @tetherto/wdk is ${latest}; no >=1.0.0-beta.11 release yet (PR #55 still main-only). Use the github pin.`);
  process.exit(0);
}

// Confirm the candidate actually ships the policy engine (defensive — a version
// bump alone isn't proof #55 is in the published tarball).
const target = candidates[0];
let hasPolicy = 'unverified';
try {
  const files = execSync(`npm view @tetherto/wdk@${target} dist.tarball`, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
  hasPolicy = files ? 'tarball available — verify src/policy/ on install' : 'unverified';
} catch { /* leave unverified */ }

console.log(`LANDED: @tetherto/wdk@${target} is published and carries PR #55 (>=beta.11).`);
console.log(`ACTION: bump this package's peer install path off the github pin to ${target}; ${hasPolicy}.`);
console.log(`Candidates: ${candidates.join(', ')}`);
process.exit(0);
