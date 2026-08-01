#!/usr/bin/env node
/**
 * DEPRISK CLI — dependency vulnerability scanner
 * Runs the same logic as the browser dashboard, but from a terminal —
 * which is what a CI/CD pipeline needs, since a pipeline can't click buttons.
 *
 * Usage:
 *   node deprisk.js --path ./requirements.txt --path ./package.json --fail-on high
 *
 * Exit codes (this is what makes CI/CD "gating" possible):
 *   0 = scan completed, no findings at/above the --fail-on threshold
 *   1 = scan completed, findings AT or ABOVE the --fail-on threshold were found
 *   2 = scan itself errored (bad input, network failure, etc.)
 */

const fs = require('fs');
const path = require('path');

// ---------------- CLI argument parsing ----------------
function parseArgs(argv) {
  const args = { paths: [], failOn: 'high', sarifOut: null, quiet: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--path') { args.paths.push(argv[++i]); }
    else if (a === '--fail-on') { args.failOn = argv[++i].toLowerCase(); }
    else if (a === '--sarif-out') { args.sarifOut = argv[++i]; }
    else if (a === '--quiet') { args.quiet = true; }
    else if (a === '--help' || a === '-h') { printHelp(); process.exit(0); }
  }
  return args;
}

function printHelp() {
  console.log(`
DEPRISK CLI — dependency vulnerability scanner

Options:
  --path <file>         Manifest file to scan (repeatable). Supports package.json,
                         package-lock.json (recommended — includes transitive
                         dependencies), requirements.txt, pom.xml.
  --fail-on <level>     Exit non-zero if any finding is at/above this severity.
                         One of: critical, high, medium, low, none (default: high)
  --sarif-out <file>    Write results in SARIF format to this path (for GitHub
                         Code Scanning / GitLab / most security dashboards).
  --quiet               Suppress the human-readable table, only print the summary line.
  --help                Show this message.

Example:
  node deprisk.js --path requirements.txt --path package.json --fail-on high --sarif-out results.sarif
`);
}

// ---------------- Parsers (same logic as the browser dashboard) ----------------
function detectKind(filename) {
  const f = filename.toLowerCase();
  if (f.endsWith('package-lock.json')) return 'npm-lock';
  if (f.endsWith('package.json')) return 'npm';
  if (f.includes('requirements') && f.endsWith('.txt')) return 'pypi';
  if (f.endsWith('pom.xml')) return 'maven';
  return null;
}

function cleanNpmVersion(v) {
  if (typeof v !== 'string') return null;
  if (v.startsWith('http') || v.startsWith('git') || v.startsWith('file:') || v.startsWith('workspace:') || v === '*' || v.toLowerCase() === 'latest') return null;
  let cleaned = v.trim().replace(/^[~^>=<\s]+/, '').split(/[\s|<>]/)[0].replace(/\.x$/, '').replace(/\.\*$/, '');
  if (!/^\d+\.\d+\.\d+/.test(cleaned)) return null;
  return cleaned;
}

// Reads package-lock.json — this is what makes the scanner see TRANSITIVE
// (indirect) dependencies, not just what's declared in package.json. Most
// real-world CVEs live here, not in the top-level manifest.
//
// Handles two lockfile shapes:
//  - Modern (npm v7+, lockfileVersion 2 or 3): a flat "packages" object keyed
//    by install path, e.g. "node_modules/lodash" or
//    "node_modules/@scope/name" or nested "node_modules/a/node_modules/b".
//  - Legacy (npm v5/v6, lockfileVersion 1): a nested "dependencies" tree,
//    where each dependency can itself contain a "dependencies" object for
//    its own children — walked recursively.
function parsePackageLockJson(text, filename) {
  const deps = [];
  let json;
  try { json = JSON.parse(text); } catch (e) { warn(`${filename}: invalid JSON — skipped.`); return deps; }

  if (json.packages) {
    Object.entries(json.packages).forEach(([installPath, info]) => {
      if (!installPath || !info || !info.version) return; // "" is the root project itself — skip
      const idx = installPath.lastIndexOf('node_modules/');
      if (idx === -1) return;
      const name = installPath.slice(idx + 'node_modules/'.length);
      deps.push({ name, version: info.version, ecosystem: 'npm', source: filename });
    });
  } else if (json.dependencies) {
    (function walk(depsObj) {
      Object.entries(depsObj).forEach(([name, info]) => {
        if (info && info.version) deps.push({ name, version: info.version, ecosystem: 'npm', source: filename });
        if (info && info.dependencies) walk(info.dependencies);
      });
    })(json.dependencies);
  } else {
    warn(`${filename}: unrecognized lockfile format — no "packages" or "dependencies" key found.`);
  }
  return deps;
}

function parsePackageJson(text, filename) {
  const deps = [];
  let json;
  try { json = JSON.parse(text); } catch (e) { warn(`${filename}: invalid JSON — skipped.`); return deps; }
  ['dependencies', 'devDependencies', 'optionalDependencies'].forEach(sec => {
    if (json[sec]) {
      Object.entries(json[sec]).forEach(([name, rawVersion]) => {
        const version = cleanNpmVersion(rawVersion);
        if (version) deps.push({ name, version, ecosystem: 'npm', source: filename });
      });
    }
  });
  return deps;
}

function parseRequirementsTxt(text, filename) {
  const deps = [];
  text.split('\n').forEach(line => {
    let l = line.trim();
    if (!l || l.startsWith('#') || l.startsWith('-r') || l.startsWith('-e') || l.startsWith('--')) return;
    l = l.split(';')[0].trim();
    l = l.split('#')[0].trim();
    if (!l) return;
    const m = l.match(/^([A-Za-z0-9_.\-\[\]]+?)\s*(==|>=|<=|~=|!=|>|<)\s*([A-Za-z0-9.\-]+)/);
    if (m) {
      const name = m[1].replace(/\[.*?\]/, '');
      deps.push({ name, version: m[3], ecosystem: 'PyPI', source: filename });
    }
  });
  return deps;
}

// Lightweight regex-based pom.xml parser — deliberately avoids an XML DOM
// dependency so this CLI has zero install steps in a pipeline.
function parsePomXml(text, filename) {
  const deps = [];
  const props = {};
  const propsBlockMatch = text.match(/<properties>([\s\S]*?)<\/properties>/);
  if (propsBlockMatch) {
    const propRe = /<([\w.\-]+)>([^<]*)<\/\1>/g;
    let pm;
    while ((pm = propRe.exec(propsBlockMatch[1]))) props[pm[1]] = pm[2].trim();
  }
  const depRe = /<dependency>([\s\S]*?)<\/dependency>/g;
  let dm;
  while ((dm = depRe.exec(text))) {
    const block = dm[1];
    const g = (block.match(/<groupId>([^<]*)<\/groupId>/) || [])[1];
    const a = (block.match(/<artifactId>([^<]*)<\/artifactId>/) || [])[1];
    const v = (block.match(/<version>([^<]*)<\/version>/) || [])[1];
    if (!g || !a || !v) continue;
    let version = v.trim();
    const propMatch = version.match(/^\$\{(.+)\}$/);
    if (propMatch) {
      version = props[propMatch[1]];
      if (!version) { warn(`${filename}: could not resolve version property for ${g.trim()}:${a.trim()} — skipped.`); continue; }
    }
    deps.push({ name: `${g.trim()}:${a.trim()}`, version, ecosystem: 'Maven', source: filename });
  }
  return deps;
}

// ---------------- CVSS v3.1 base score (same formula as the dashboard) ----------------
function cvss3BaseScore(vector) {
  const parts = vector.split('/');
  const m = {};
  parts.forEach(p => { const [k, v] = p.split(':'); if (k && v) m[k] = v; });
  if (!m.AV || !m.AC || !m.PR || !m.UI || !m.S || !m.C || !m.I || !m.A) return null;
  const AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }[m.AV];
  const AC = { L: 0.77, H: 0.44 }[m.AC];
  const PRu = { N: 0.85, L: 0.62, H: 0.27 };
  const PRc = { N: 0.85, L: 0.68, H: 0.5 };
  const UI = { N: 0.85, R: 0.62 }[m.UI];
  const scoped = m.S === 'C';
  const PR = (scoped ? PRc : PRu)[m.PR];
  const CIA = { N: 0, L: 0.22, H: 0.56 };
  const C = CIA[m.C], I = CIA[m.I], A = CIA[m.A];
  if ([AV, AC, PR, UI, C, I, A].some(x => x === undefined)) return null;
  const ISS = 1 - ((1 - C) * (1 - I) * (1 - A));
  let impact = scoped ? (7.52 * (ISS - 0.029) - 3.25 * Math.pow(ISS - 0.02, 15)) : (6.42 * ISS);
  const exploitability = 8.22 * AV * AC * PR * UI;
  if (impact <= 0) return 0;
  let base = scoped ? Math.min(1.08 * (impact + exploitability), 10) : Math.min(impact + exploitability, 10);
  return Math.ceil(base * 10) / 10;
}

function bucketFromScore(score) {
  if (score === null || score === undefined) return null;
  if (score >= 9) return 'CRITICAL';
  if (score >= 7) return 'HIGH';
  if (score >= 4) return 'MEDIUM';
  if (score > 0) return 'LOW';
  return null;
}

function classifySeverity(vuln) {
  const dbSev = vuln.database_specific && vuln.database_specific.severity;
  if (dbSev) {
    const map = { CRITICAL: 'CRITICAL', HIGH: 'HIGH', MODERATE: 'MEDIUM', MEDIUM: 'MEDIUM', LOW: 'LOW' };
    const bucket = map[dbSev.toUpperCase()];
    if (bucket) return { bucket, score: null, basis: 'advisory-reported' };
  }
  if (Array.isArray(vuln.severity)) {
    for (const s of vuln.severity) {
      if (s.type && s.type.startsWith('CVSS_V3')) {
        const score = cvss3BaseScore(s.score);
        if (score !== null) {
          const bucket = bucketFromScore(score);
          if (bucket) return { bucket, score, basis: 'cvss3-computed' };
        }
      }
    }
  }
  return { bucket: 'MEDIUM', score: null, basis: 'unscored (defaulted)' };
}

function extractFixedVersions(vuln, ecosystem, pkgName) {
  const fixes = new Set();
  (vuln.affected || []).forEach(aff => {
    if (!aff.package) return;
    if (aff.package.ecosystem !== ecosystem || aff.package.name !== pkgName) return;
    (aff.ranges || []).forEach(r => (r.events || []).forEach(ev => { if (ev.fixed) fixes.add(ev.fixed); }));
  });
  return Array.from(fixes);
}

// ---------------- OSV querying ----------------
async function queryOSVBatch(deps) {
  const queries = deps.map(d => ({ package: { name: d.name, ecosystem: d.ecosystem }, version: d.version }));
  const res = await fetch('https://api.osv.dev/v1/querybatch', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ queries })
  });
  if (!res.ok) throw new Error(`OSV querybatch failed: HTTP ${res.status}`);
  const data = await res.json();
  return data.results || [];
}

async function fetchVulnDetail(id) {
  const res = await fetch(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`);
  if (!res.ok) throw new Error(`OSV vuln fetch failed for ${id}: HTTP ${res.status}`);
  return res.json();
}

async function fetchAllDetails(ids) {
  const details = {};
  const queue = [...ids];
  const concurrency = 6;
  async function worker() {
    while (queue.length) {
      const id = queue.shift();
      try { details[id] = await fetchVulnDetail(id); } catch (e) { /* skip individual failures */ }
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, ids.length || 1) }, worker));
  return details;
}

// ---------------- SARIF export ----------------
// SARIF (Static Analysis Results Interchange Format) is the JSON schema GitHub
// Code Scanning, GitLab, and most security dashboards understand natively.
// Producing this is what makes a tool "pluggable" into a real pipeline instead
// of a standalone report nobody automated ever reads.
function toSARIF(findings) {
  const severityToSarifLevel = { CRITICAL: 'error', HIGH: 'error', MEDIUM: 'warning', LOW: 'note' };
  const rules = [];
  const seenRules = new Set();
  findings.forEach(f => {
    if (!seenRules.has(f.vulnId)) {
      seenRules.add(f.vulnId);
      // GitHub's SARIF validator expects "security-severity" to be a valid
      // numeric string if present at all — an empty string is invalid and
      // triggers a "tool is reporting errors" configuration warning on the
      // whole run. So when we have no computed CVSS score (advisory-reported
      // severity only), we omit the property entirely rather than setting
      // it to ''.
      const properties = {};
      if (f.score !== null) properties['security-severity'] = String(f.score);
      rules.push({
        id: f.vulnId,
        name: f.vulnId,
        shortDescription: { text: f.summary.slice(0, 120) },
        fullDescription: { text: f.summary },
        helpUri: f.link,
        properties
      });
    }
  });
  const results = findings.map(f => ({
    ruleId: f.vulnId,
    level: severityToSarifLevel[f.bucket] || 'warning',
    message: {
      text: `${f.pkgName}@${f.pkgVersion} (${f.ecosystem}) is affected by ${f.vulnId} [${f.bucket}]. ${f.fixedVersions.length ? 'Upgrade to ' + f.fixedVersions.join(', ') + '.' : 'No fix published yet.'}`
    },
    locations: [{
      physicalLocation: {
        artifactLocation: { uri: f.sources[0] || 'unknown' }
      }
    }]
  }));
  return {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'DEPRISK',
          informationUri: 'https://osv.dev',
          version: '1.0.0',
          rules
        }
      },
      results
    }]
  };
}

// ---------------- Helpers ----------------
const severityRank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, NONE: 0 };
function warn(msg) { console.error(`[warn] ${msg}`); }

// ---------------- Main ----------------
async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.paths.length === 0) { printHelp(); process.exit(2); }

  let allDeps = [];
  for (const p of args.paths) {
    if (!fs.existsSync(p)) { warn(`File not found: ${p}`); continue; }
    const filename = path.basename(p);
    const kind = detectKind(filename);
    if (!kind) { warn(`Unrecognized manifest type: ${filename}`); continue; }
    const text = fs.readFileSync(p, 'utf8');
    if (kind === 'npm-lock') allDeps = allDeps.concat(parsePackageLockJson(text, filename));
    else if (kind === 'npm') allDeps = allDeps.concat(parsePackageJson(text, filename));
    else if (kind === 'pypi') allDeps = allDeps.concat(parseRequirementsTxt(text, filename));
    else if (kind === 'maven') allDeps = allDeps.concat(parsePomXml(text, filename));
  }

  const depMap = new Map();
  allDeps.forEach(d => {
    const key = `${d.ecosystem}::${d.name}::${d.version}`;
    if (depMap.has(key)) depMap.get(key).sources.add(d.source);
    else depMap.set(key, { ...d, sources: new Set([d.source]) });
  });
  const uniqueDeps = Array.from(depMap.values());

  if (uniqueDeps.length === 0) {
    console.error('No resolvable dependencies with pinned versions were found.');
    process.exit(2);
  }

  console.error(`Scanning ${uniqueDeps.length} unique package(s)...`);

  let batchResults;
  try {
    batchResults = await queryOSVBatch(uniqueDeps);
  } catch (e) {
    console.error(`ERROR: could not reach OSV.dev — ${e.message}`);
    process.exit(2);
  }

  const idSet = new Set();
  batchResults.forEach(r => (r.vulns || []).forEach(v => idSet.add(v.id)));
  const detailMap = idSet.size ? await fetchAllDetails(Array.from(idSet)) : {};

  const findings = [];
  uniqueDeps.forEach((dep, idx) => {
    const vulnRefs = (batchResults[idx] && batchResults[idx].vulns) || [];
    vulnRefs.forEach(vref => {
      const detail = detailMap[vref.id];
      if (!detail) return;
      const { bucket, score, basis } = classifySeverity(detail);
      const fixedVersions = extractFixedVersions(detail, dep.ecosystem, dep.name);
      findings.push({
        pkgName: dep.name, pkgVersion: dep.version, ecosystem: dep.ecosystem,
        sources: Array.from(dep.sources), vulnId: detail.id,
        summary: detail.summary || (detail.details ? detail.details.slice(0, 140) : 'No summary provided.'),
        bucket, score, basis, fixedVersions, link: `https://osv.dev/vulnerability/${detail.id}`
      });
    });
  });

  findings.sort((a, b) => severityRank[b.bucket] - severityRank[a.bucket] || (b.score || 0) - (a.score || 0));

  if (!args.quiet) {
    console.log('');
    console.log('SEVERITY  PACKAGE                                   ADVISORY          CVSS   FIX');
    console.log('-'.repeat(100));
    findings.forEach(f => {
      console.log(
        f.bucket.padEnd(9) +
        `${f.pkgName}@${f.pkgVersion}`.padEnd(42) +
        f.vulnId.padEnd(18) +
        (f.score !== null ? f.score.toFixed(1) : '—').padEnd(7) +
        (f.fixedVersions.length ? f.fixedVersions.join(', ') : 'no fix yet')
      );
    });
    console.log('');
  }

  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  findings.forEach(f => counts[f.bucket]++);
  console.log(`Summary: ${uniqueDeps.length} packages scanned | ${findings.length} findings | ` +
    `Critical: ${counts.CRITICAL}  High: ${counts.HIGH}  Medium: ${counts.MEDIUM}  Low: ${counts.LOW}`);

  if (args.sarifOut) {
    fs.writeFileSync(args.sarifOut, JSON.stringify(toSARIF(findings), null, 2));
    console.log(`SARIF written to ${args.sarifOut}`);
  }

  // ---- Gating logic: this is the actual "DevSecOps" part ----
  // Decide whether this scan should FAIL the pipeline based on --fail-on.
  const thresholds = { critical: 4, high: 3, medium: 2, low: 1, none: 99 };
  const thresholdRank = thresholds[args.failOn] ?? 3;
  const worstFinding = findings.reduce((max, f) => Math.max(max, severityRank[f.bucket]), 0);

  if (worstFinding >= thresholdRank) {
    console.error(`\nFAILING: findings at or above "${args.failOn}" threshold were found.`);
    process.exit(1);
  }
  process.exit(0);
}

main();
