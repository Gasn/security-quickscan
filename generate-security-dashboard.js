#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');

const REPORT_ROOT = 'security-reports';
const OUTPUT_NAME = 'security-dashboard.html';
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info', 'unknown'];
const STATUS_RANK = { pass: 0, warning: 1, fail: 2, incomplete: 3, 'not-run': 4 };

function usage() {
  console.log(`Usage:
  node generate-security-dashboard.js [report-dir]

If no report directory is provided, the newest subdirectory under security-reports/
is used. The dashboard is written to <report-dir>/${OUTPUT_NAME}.`);
}

function exists(file) {
  return fs.existsSync(file);
}

function readText(file) {
  try {
    return fs.readFileSync(file, 'utf8');
  } catch {
    return null;
  }
}

function readJson(file) {
  const text = readText(file);
  if (!text || !text.trim()) return null;
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function htmlEscape(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function redact(value) {
  if (value == null) return '';
  let text = String(value);
  text = text.replace(/-----BEGIN [^-]+PRIVATE KEY-----[\s\S]*?-----END [^-]+PRIVATE KEY-----/g, '[redacted private key]');
  text = text.replace(/\b(AKIA|ASIA)[A-Z0-9]{16}\b/g, '$1...[redacted]');
  text = text.replace(/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, '[redacted jwt]');
  text = text.replace(/(secret|token|api[_-]?key|password|credential)(["'\s:=]+)([^"'\s,;]+)/gi, '$1$2[redacted]');
  return text.length > 280 ? `${text.slice(0, 277)}...` : text;
}

function normalizeSeverity(value, fallback = 'unknown') {
  const raw = String(value ?? '').trim().toLowerCase();
  if (!raw) return fallback;
  if (['critical', 'crit', 'very_high', 'risk-3'].includes(raw)) return 'critical';
  if (['high', 'error', 'important', 'risk-2'].includes(raw)) return 'high';
  if (['medium', 'moderate', 'warning', 'warn', 'risk-1'].includes(raw)) return 'medium';
  if (['low', 'note'].includes(raw)) return 'low';
  if (['info', 'informational', 'none', 'negligible'].includes(raw)) return 'info';
  return fallback;
}

function severityFromZap(alert) {
  if (alert.riskcode != null) {
    const code = Number(alert.riskcode);
    if (code >= 3) return 'high';
    if (code === 2) return 'medium';
    if (code === 1) return 'low';
    if (code === 0) return 'info';
  }
  return normalizeSeverity(alert.riskdesc || alert.risk || alert.confidence, 'unknown');
}

function statusLabel(status) {
  return {
    pass: 'Pass',
    warning: 'Warning',
    fail: 'Fail',
    incomplete: 'Incomplete',
    'not-run': 'Not run',
  }[status] || status;
}

function resolveReportDir(arg) {
  if (arg === '--help' || arg === '-h') {
    usage();
    process.exit(0);
  }
  const cwd = process.cwd();
  if (arg) {
    const candidate = path.resolve(cwd, arg);
    if (!exists(candidate) || !fs.statSync(candidate).isDirectory()) {
      throw new Error(`Report directory not found: ${candidate}`);
    }
    return candidate;
  }
  const root = path.resolve(cwd, REPORT_ROOT);
  if (!exists(root)) throw new Error(`No ${REPORT_ROOT}/ directory found.`);
  const dirs = fs.readdirSync(root, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => {
      const full = path.join(root, entry.name);
      return { full, mtimeMs: fs.statSync(full).mtimeMs };
    })
    .sort((a, b) => b.mtimeMs - a.mtimeMs);
  if (dirs.length) return dirs[0].full;
  return root;
}

function firstExisting(reportDir, names) {
  for (const name of names) {
    const file = path.join(reportDir, name);
    if (exists(file)) return file;
  }
  return null;
}

function addFinding(ctx, finding) {
  ctx.findings.push({
    severity: normalizeSeverity(finding.severity),
    tool: finding.tool || 'Unknown',
    title: redact(finding.title || 'Untitled finding'),
    affected: redact(finding.affected || ''),
    risk: redact(finding.risk || ''),
    action: redact(finding.action || 'Review and remediate if applicable.'),
    status: finding.status || 'Open',
  });
}

function createTool(ctx, key, label, files) {
  const file = firstExisting(ctx.reportDir, files);
  ctx.tools[key] = { label, status: file ? 'pass' : 'not-run', summary: file ? `Parsed ${path.basename(file)}` : 'Not run', file, count: 0 };
  return ctx.tools[key];
}

function readReason(reportDir, name, fallback = '') {
  const reason = readText(path.join(reportDir, `${name}.reason`))?.trim();
  return reason || fallback;
}

function statusWithReason(status, reason) {
  const label = statusLabel(status);
  return status === 'not-run' && reason ? `${label}: ${reason}` : label;
}

function parseGitleaks(ctx) {
  const tool = createTool(ctx, 'gitleaks', 'Gitleaks', ['gitleaks-git.json', 'gitleaks-dir.json']);
  const files = ['gitleaks-git.json', 'gitleaks-dir.json'].map((name) => path.join(ctx.reportDir, name)).filter(exists);
  if (!files.length) return;
  let count = 0;
  for (const file of files) {
    const data = readJson(file);
    if (!Array.isArray(data)) {
      tool.status = 'warning';
      tool.summary = `Could not parse ${path.basename(file)}`;
      continue;
    }
    for (const item of data) {
      const fp = String(item.Fingerprint || item.fingerprint || item.Description || '').toLowerCase();
      const isFalsePositive = item.FalsePositive === true || item.false_positive === true || fp.includes('false-positive') || fp.includes('false positive');
      if (isFalsePositive) continue;
      count += 1;
      addFinding(ctx, {
        severity: 'critical',
        tool: 'Gitleaks',
        title: item.RuleID || item.Description || 'Secret detected',
        affected: `${item.File || item.file || 'unknown'}${item.StartLine || item.line ? `:${item.StartLine || item.line}` : ''}`,
        risk: 'Potential secret exposure. Full secret value is redacted by the scanner/dashboard.',
        action: 'Rotate the secret, remove it from source/history, and verify it is no longer valid.',
      });
    }
  }
  tool.count = count;
  tool.status = count > 0 ? 'fail' : 'pass';
  tool.summary = count > 0 ? `${count} secret finding(s)` : 'No secrets found';
}

function parseSemgrepJson(ctx, file) {
  const data = readJson(file);
  if (!data || !Array.isArray(data.results)) return false;
  for (const result of data.results) {
    const extra = result.extra || {};
    const metadata = extra.metadata || {};
    addFinding(ctx, {
      severity: normalizeSeverity(metadata.severity || metadata.impact || extra.severity, 'medium'),
      tool: 'Semgrep',
      title: extra.message || result.check_id || 'SAST finding',
      affected: `${result.path || 'unknown'}${result.start?.line ? `:${result.start.line}` : ''}`,
      risk: [result.check_id, metadata.cwe, metadata.owasp].flat().filter(Boolean).join(' | '),
      action: 'Review the data flow and apply the rule guidance or documented compensating control.',
    });
  }
  return true;
}

function parseSemgrepSarif(ctx, file) {
  const data = readJson(file);
  if (!data || !Array.isArray(data.runs)) return false;
  for (const run of data.runs) {
    const rules = new Map((run.tool?.driver?.rules || []).map((rule) => [rule.id, rule]));
    for (const result of run.results || []) {
      const rule = rules.get(result.ruleId) || {};
      const location = result.locations?.[0]?.physicalLocation || {};
      const artifact = location.artifactLocation?.uri || '';
      const line = location.region?.startLine;
      addFinding(ctx, {
        severity: normalizeSeverity(result.properties?.severity || rule.properties?.severity || result.level, 'medium'),
        tool: 'Semgrep',
        title: result.message?.text || rule.name || result.ruleId || 'SAST finding',
        affected: `${artifact || 'unknown'}${line ? `:${line}` : ''}`,
        risk: result.ruleId || '',
        action: 'Review the matched rule and remediate or document a false positive.',
      });
    }
  }
  return true;
}

function parseSemgrep(ctx) {
  const tool = createTool(ctx, 'semgrep', 'Semgrep', ['semgrep.json', 'semgrep.sarif', 'semgrep-auto.json', 'semgrep-owasp.json']);
  const before = ctx.findings.length;
  const files = ['semgrep.json', 'semgrep.sarif', 'semgrep-auto.json', 'semgrep-owasp.json'].map((name) => path.join(ctx.reportDir, name)).filter(exists);
  if (!files.length) return;
  let parsed = 0;
  for (const file of files) {
    const ok = file.endsWith('.sarif') ? parseSemgrepSarif(ctx, file) : parseSemgrepJson(ctx, file);
    if (ok) parsed += 1;
  }
  tool.count = ctx.findings.length - before;
  tool.status = parsed ? (tool.count ? 'warning' : 'pass') : 'warning';
  tool.summary = parsed ? `${tool.count} SAST finding(s)` : 'Report present but could not be parsed';
}

function parseTrivy(ctx) {
  const tool = createTool(ctx, 'trivy', 'Trivy', ['trivy.json']);
  if (!tool.file) return;
  const data = readJson(tool.file);
  if (!data || !Array.isArray(data.Results)) {
    tool.status = 'warning';
    tool.summary = 'Report present but could not be parsed';
    return;
  }
  let count = 0;
  for (const result of data.Results) {
    for (const vuln of result.Vulnerabilities || []) {
      count += 1;
      addFinding(ctx, {
        severity: normalizeSeverity(vuln.Severity, 'unknown'),
        tool: 'Trivy',
        title: `${vuln.VulnerabilityID || 'Vulnerability'} ${vuln.Title || ''}`.trim(),
        affected: `${vuln.PkgName || 'package'} ${vuln.InstalledVersion || ''}${result.Target ? ` in ${result.Target}` : ''}`,
        risk: vuln.Description || vuln.PrimaryURL || '',
        action: vuln.FixedVersion ? `Upgrade to ${vuln.FixedVersion} or later.` : 'Review advisory and update, replace, or document accepted risk.',
      });
    }
  }
  tool.count = count;
  tool.status = count ? 'warning' : 'pass';
  tool.summary = `${count} dependency vulnerability finding(s)`;
}

function parseOsv(ctx) {
  const tool = createTool(ctx, 'osv', 'OSV-Scanner', ['osv.json']);
  if (!tool.file) return;
  const data = readJson(tool.file);
  if (!data) {
    tool.status = 'warning';
    tool.summary = 'Report present but could not be parsed';
    return;
  }
  const results = Array.isArray(data.results) ? data.results : [];
  let count = 0;
  for (const result of results) {
    const packages = result.packages || [];
    for (const pkg of packages) {
      const info = pkg.package || pkg;
      for (const vuln of pkg.vulnerabilities || result.vulnerabilities || []) {
        count += 1;
        addFinding(ctx, {
          severity: normalizeSeverity(vuln.database_specific?.severity || vuln.severity?.[0]?.score, 'unknown'),
          tool: 'OSV-Scanner',
          title: `${vuln.id || 'OSV vulnerability'} ${vuln.summary || ''}`.trim(),
          affected: `${info.ecosystem || ''}:${info.name || 'package'} ${info.version || ''}`.replace(/^:/, ''),
          risk: (vuln.aliases || []).join(', '),
          action: 'Update to a non-vulnerable version or document the accepted risk.',
        });
      }
    }
  }
  tool.count = count;
  tool.status = count ? 'warning' : 'pass';
  tool.summary = `${count} dependency vulnerability finding(s)`;
}

function parseCheckov(ctx) {
  const tool = createTool(ctx, 'checkov', 'Checkov', ['checkov.json']);
  if (!tool.file) return;
  const data = readJson(tool.file);
  if (!data) {
    tool.status = 'warning';
    tool.summary = 'Report present but could not be parsed';
    return;
  }
  const failed = Array.isArray(data.results?.failed_checks) ? data.results.failed_checks
    : Array.isArray(data.failed_checks) ? data.failed_checks
      : Array.isArray(data) ? data.flatMap((entry) => entry.results?.failed_checks || []) : [];
  for (const check of failed) {
    addFinding(ctx, {
      severity: normalizeSeverity(check.severity, 'medium'),
      tool: 'Checkov',
      title: `${check.check_id || 'Checkov'} ${check.check_name || ''}`.trim(),
      affected: [check.file_path, check.resource].filter(Boolean).join(' | '),
      risk: check.guideline || check.check_result?.result || '',
      action: 'Adjust infrastructure/configuration or document why the control is not applicable.',
    });
  }
  tool.count = failed.length;
  tool.status = failed.length ? 'warning' : 'pass';
  tool.summary = `${failed.length} infrastructure finding(s)`;
}

function parseZap(ctx) {
  const tool = createTool(ctx, 'zap', 'OWASP ZAP', ['zap-report.json', 'zap-report.html']);
  if (!tool.file) {
    tool.summary = `Not run: ${readReason(ctx.reportDir, 'zap', 'no target URL provided')}`;
    return;
  }
  if (path.basename(tool.file) === 'zap-report.html') {
    tool.status = 'pass';
    tool.summary = 'HTML only; detailed parsing unavailable';
    return;
  }
  const data = readJson(tool.file);
  if (!data) {
    tool.status = 'warning';
    tool.summary = 'Report present but could not be parsed';
    return;
  }
  const alerts = Array.isArray(data.site) ? data.site.flatMap((site) => site.alerts || []) : data.alerts || [];
  for (const alert of alerts) {
    addFinding(ctx, {
      severity: severityFromZap(alert),
      tool: 'OWASP ZAP',
      title: alert.alert || alert.name || 'ZAP alert',
      affected: alert.url || alert.uri || alert.instances?.[0]?.uri || '',
      risk: alert.desc || alert.description || alert.riskdesc || '',
      action: alert.solution || 'Review dynamic scan alert and remediate or document accepted risk.',
    });
  }
  tool.count = alerts.length;
  tool.status = alerts.length ? 'warning' : 'pass';
  tool.summary = `${alerts.length} dynamic scan finding(s)`;
}

function detectLogStatus(reportDir, name) {
  const statusFile = path.join(reportDir, `${name}.status`);
  const status = readText(statusFile)?.trim().toLowerCase();
  if (['pass', 'fail', 'not-run'].includes(status)) return status;
  const logFile = firstExisting(reportDir, [`${name}.log`, `pnpm-${name}.txt`, `npm-${name}.txt`]);
  if (!logFile) return 'not-run';
  const log = readText(logFile) || '';
  if (/(\bexit\s*(code)?\s*[=:]\s*[1-9]\d*\b|\bfailed\b|\berror\b|ELIFECYCLE|ERR_PNPM_RECURSIVE_RUN_FIRST_FAIL|Command failed)/i.test(log)) return 'fail';
  return 'pass';
}

function detectCheck(reportDir, name) {
  const status = detectLogStatus(reportDir, name);
  const reason = readReason(reportDir, name, status === 'not-run' ? `No ${name} script found in package.json` : '');
  return { status, reason };
}

function parseBuildChecks(ctx) {
  const checks = {
    build: detectCheck(ctx.reportDir, 'build'),
    typecheck: detectCheck(ctx.reportDir, 'typecheck'),
    test: detectCheck(ctx.reportDir, 'test'),
  };
  const statuses = Object.fromEntries(Object.entries(checks).map(([name, check]) => [name, check.status]));
  ctx.buildStatuses = statuses;
  const values = Object.values(statuses);
  const status = values.includes('fail') ? 'fail' : values.includes('not-run') ? 'incomplete' : 'pass';
  const summaryParts = [
    ['Build', checks.build],
    ['Typecheck', checks.typecheck],
    ['Tests', checks.test],
  ].map(([label, check]) => `${label}: ${statusWithReason(check.status, check.reason)}`);
  ctx.tools.build = {
    label: 'Build/typecheck/test',
    status,
    summary: summaryParts.join(' | '),
    count: values.filter((value) => value === 'fail').length,
  };
}

function parseAudit(ctx) {
  const tool = createTool(ctx, 'audit', 'Package manager audit', ['pnpm-audit.json', 'npm-audit.json']);
  const statusFile = readText(path.join(ctx.reportDir, 'audit.status'))?.trim().toLowerCase();
  if (!tool.file) {
    if (['pass', 'fail', 'not-run'].includes(statusFile)) tool.status = statusFile;
    const reason = readReason(ctx.reportDir, 'audit', 'No package manager audit output found');
    tool.summary = statusWithReason(tool.status, reason);
    return;
  }
  const data = readJson(tool.file);
  if (!data) {
    tool.status = 'warning';
    tool.summary = 'Report present but could not be parsed';
    return;
  }
  const before = ctx.findings.length;
  if (data.advisories) {
    for (const advisory of Object.values(data.advisories)) {
      addFinding(ctx, {
        severity: normalizeSeverity(advisory.severity, 'unknown'),
        tool: path.basename(tool.file).startsWith('npm') ? 'npm audit' : 'pnpm audit',
        title: advisory.title || advisory.module_name || 'Dependency advisory',
        affected: advisory.module_name || advisory.name || '',
        risk: advisory.overview || advisory.url || '',
        action: advisory.recommendation || 'Upgrade the affected dependency.',
      });
    }
  }
  for (const vuln of Object.values(data.vulnerabilities || {})) {
    addFinding(ctx, {
      severity: normalizeSeverity(vuln.severity, 'unknown'),
      tool: path.basename(tool.file).startsWith('npm') ? 'npm audit' : 'pnpm audit',
      title: vuln.title || vuln.name || 'Dependency advisory',
      affected: vuln.name || '',
      risk: (vuln.via || []).map((via) => typeof via === 'string' ? via : via.title || via.source).filter(Boolean).join(', '),
      action: vuln.fixAvailable ? 'Apply the available dependency fix.' : 'Review advisory and update, replace, or document accepted risk.',
    });
  }
  tool.count = ctx.findings.length - before;
  tool.status = tool.count ? 'warning' : 'pass';
  tool.summary = `${tool.count} package audit finding(s)`;
}

function parseAiReview(ctx) {
  const file = firstExisting(ctx.reportDir, ['ai-review.md']);
  const tool = { label: 'AI/manual review', status: 'not-run', summary: 'Not run: security-reports/ai-review.md not found', file, count: 0 };
  if (file) {
    const text = readText(file) || '';
    const match = text.match(/^\s*GO\s*:\s*(yes|no|conditional)\s*$/im);
    tool.status = 'pass';
    tool.summary = 'Completed; manual decision unknown';
    if (match?.[1].toLowerCase() === 'yes') {
      tool.summary = 'Completed; GO: yes';
    } else if (match?.[1].toLowerCase() === 'no') {
      tool.status = 'fail';
      tool.summary = 'Completed; GO: no';
    } else if (match?.[1].toLowerCase() === 'conditional') {
      tool.status = 'warning';
      tool.summary = 'Completed; GO: conditional';
    }
  }
  ctx.tools.ai = tool;
}

function parseRepoName(reportDir) {
  const summary = readText(path.join(reportDir, 'summary.md')) || '';
  const fromSummary = summary.match(/Target repo name:\s*([^\n]+)/i)?.[1]?.trim();
  if (fromSummary) return fromSummary;
  const base = path.basename(reportDir);
  return base.replace(/-\d{8}T\d{6}Z$/, '');
}

function computeSummary(ctx) {
  const severityCounts = Object.fromEntries(SEVERITIES.map((severity) => [severity, 0]));
  for (const finding of ctx.findings) severityCounts[finding.severity] += 1;
  const toolValues = Object.values(ctx.tools);
  const incomplete = toolValues.some((tool) => ['not-run', 'incomplete'].includes(tool.status));
  const secrets = ctx.findings.filter((finding) => finding.tool === 'Gitleaks').length;
  const buildFail = ctx.buildStatuses.build === 'fail';
  const typecheckFail = ctx.buildStatuses.typecheck === 'fail';
  const testsMissingOrFailed = ['fail', 'not-run'].includes(ctx.buildStatuses.test);
  const aiIncomplete = ['not-run', 'incomplete'].includes(ctx.tools.ai.status);

  let overall = 'pass';
  let recommendation = 'Go';
  const reasons = [];
  if (secrets > 0) reasons.push('verified or untriaged secret finding exists');
  if (severityCounts.critical > 0) reasons.push('critical finding exists');
  if (buildFail) reasons.push('build failed');
  if (typecheckFail) reasons.push('typecheck failed');
  if (ctx.tools.ai.status === 'fail') reasons.push('AI/manual review marked GO: no');
  if (reasons.length) {
    overall = 'fail';
    recommendation = 'No-go';
  } else {
    const warnings = [];
    if (severityCounts.high > 0) warnings.push('high findings exist');
    if (testsMissingOrFailed) warnings.push('tests are missing or failed');
    if (incomplete) warnings.push('scan outputs are incomplete');
    if (aiIncomplete) warnings.push('AI/manual review has not been completed');
    if (ctx.tools.ai.status === 'warning') warnings.push('AI/manual review is conditional');
    if (warnings.length) {
      overall = incomplete ? 'incomplete' : 'warning';
      recommendation = 'Conditional go';
      reasons.push(...warnings);
    }
  }
  ctx.summary = {
    severityCounts,
    secrets,
    dependency: ctx.findings.filter((f) => ['Trivy', 'OSV-Scanner', 'npm audit', 'pnpm audit'].includes(f.tool)).length,
    sast: ctx.findings.filter((f) => f.tool === 'Semgrep').length,
    infra: ctx.findings.filter((f) => f.tool === 'Checkov').length,
    dynamic: ctx.findings.filter((f) => f.tool === 'OWASP ZAP').length,
    overall,
    recommendation,
    reasons,
  };
}

function render(ctx) {
  const cards = [
    ['Critical findings', ctx.summary.severityCounts.critical],
    ['High findings', ctx.summary.severityCounts.high],
    ['Medium findings', ctx.summary.severityCounts.medium],
    ['Low findings', ctx.summary.severityCounts.low],
    ['Secrets found', ctx.summary.secrets],
    ['Dependency vulnerabilities', ctx.summary.dependency],
    ['SAST findings', ctx.summary.sast],
    ['Infrastructure findings', ctx.summary.infra],
    ['Dynamic scan findings', ctx.summary.dynamic],
    ['Build/typecheck/test', ctx.tools.build.summary],
  ];
  const tools = ['gitleaks', 'build', 'semgrep', 'trivy', 'osv', 'checkov', 'zap', 'audit', 'ai']
    .map((key) => ctx.tools[key])
    .filter(Boolean)
    .sort((a, b) => (STATUS_RANK[b.status] ?? 0) - (STATUS_RANK[a.status] ?? 0));
  const checklist = [
    'Secrets rotated or confirmed false positive',
    'Critical and high findings triaged',
    'Authentication and authorization paths reviewed',
    'Sensitive data exposure and logging reviewed',
    'Dependency updates or exceptions documented',
    'Infrastructure findings remediated or accepted',
    'Build and typecheck pass locally',
    'Tests pass or missing tests are explicitly accepted',
    'AI/manual review completed or marked not required',
  ];

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Security Scan Dashboard - ${htmlEscape(ctx.repoName)}</title>
  <style>
    :root { color-scheme: light; --bg: #f7f8fa; --panel: #fff; --ink: #17202a; --muted: #5c6670; --line: #d9dee5; --critical: #8b1d1d; --high: #b33a18; --medium: #a46a00; --low: #286140; --info: #315b8a; --ok: #1f6b45; }
    * { box-sizing: border-box; }
    body { margin: 0; font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif; background: var(--bg); color: var(--ink); line-height: 1.45; }
    header { padding: 28px 32px 20px; border-bottom: 1px solid var(--line); background: #fff; }
    main { padding: 24px 32px 40px; max-width: 1500px; margin: 0 auto; }
    h1 { margin: 0 0 8px; font-size: 28px; letter-spacing: 0; }
    h2 { margin: 28px 0 12px; font-size: 18px; }
    .meta, .muted { color: var(--muted); }
    .topline { display: flex; flex-wrap: wrap; gap: 10px 18px; align-items: center; }
    .badge { display: inline-flex; align-items: center; min-height: 28px; padding: 3px 10px; border: 1px solid var(--line); border-radius: 6px; font-weight: 700; background: #fff; }
    .badge.pass { color: var(--ok); border-color: #a8cfba; }
    .badge.warning, .badge.incomplete { color: var(--medium); border-color: #dec281; }
    .badge.fail { color: var(--critical); border-color: #d7aaaa; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; }
    .card { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 14px; min-height: 92px; }
    .card .label { color: var(--muted); font-size: 13px; }
    .card .value { margin-top: 8px; font-size: 24px; font-weight: 800; overflow-wrap: anywhere; }
    .tools { grid-template-columns: repeat(auto-fit, minmax(230px, 1fr)); }
    .tool-title { display: flex; justify-content: space-between; gap: 10px; align-items: start; font-weight: 800; }
    .tool-summary { margin-top: 10px; color: var(--muted); font-size: 14px; }
    table { width: 100%; border-collapse: collapse; background: #fff; border: 1px solid var(--line); border-radius: 8px; overflow: hidden; }
    th, td { padding: 10px 12px; text-align: left; vertical-align: top; border-bottom: 1px solid var(--line); font-size: 14px; }
    th { background: #eef1f4; font-size: 12px; text-transform: uppercase; letter-spacing: 0; color: #3b4650; }
    tr:last-child td { border-bottom: 0; }
    .sev { font-weight: 800; text-transform: capitalize; }
    .sev.critical { color: var(--critical); }
    .sev.high { color: var(--high); }
    .sev.medium { color: var(--medium); }
    .sev.low { color: var(--low); }
    .sev.info { color: var(--info); }
    .recommendation { background: #fff; border: 1px solid var(--line); border-radius: 8px; padding: 16px; }
    .checklist { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 8px 18px; background: #fff; border: 1px solid var(--line); border-radius: 8px; padding: 16px; }
    .checkitem { display: flex; gap: 8px; align-items: flex-start; }
    .box { width: 15px; height: 15px; border: 1px solid #6f7b86; margin-top: 3px; flex: 0 0 auto; }
    @media (max-width: 760px) { header, main { padding-left: 16px; padding-right: 16px; } table { display: block; overflow-x: auto; } }
    @media print { body { background: #fff; } header, main { padding: 16px; } .card, table, .recommendation, .checklist { break-inside: avoid; } }
  </style>
</head>
<body>
  <header>
    <h1>Security Scan Dashboard</h1>
    <div class="topline">
      <span class="meta">Repo: <strong>${htmlEscape(ctx.repoName)}</strong></span>
      <span class="meta">Generated: <strong>${htmlEscape(ctx.generatedAt)}</strong></span>
      <span class="badge ${htmlEscape(ctx.summary.overall)}">Overall: ${htmlEscape(statusLabel(ctx.summary.overall))}</span>
      <span class="badge ${ctx.summary.recommendation === 'No-go' ? 'fail' : ctx.summary.recommendation === 'Go' ? 'pass' : 'warning'}">${htmlEscape(ctx.summary.recommendation)}</span>
    </div>
  </header>
  <main>
    <section class="grid">${cards.map(([label, value]) => `<div class="card"><div class="label">${htmlEscape(label)}</div><div class="value">${htmlEscape(value)}</div></div>`).join('')}</section>

    <h2>Per-Tool Status</h2>
    <section class="grid tools">${tools.map((tool) => `<div class="card"><div class="tool-title"><span>${htmlEscape(tool.label)}</span><span class="badge ${htmlEscape(tool.status)}">${htmlEscape(statusLabel(tool.status))}</span></div><div class="tool-summary">${htmlEscape(tool.summary)}</div></div>`).join('')}</section>

    <h2>Go/No-Go Recommendation</h2>
    <section class="recommendation">
      <p><strong>${htmlEscape(ctx.summary.recommendation)}.</strong> ${ctx.summary.reasons.length ? htmlEscape(ctx.summary.reasons.join('; ')) : 'No blocking conditions detected by the aggregated scan output.'}</p>
      <p class="muted">This dashboard is local-only and summarizes scanner output. It does not replace human review for business logic, authorization, data exposure, or production deployment decisions.</p>
    </section>

    <h2>Finding Register</h2>
    <table>
      <thead><tr><th>Severity</th><th>Tool</th><th>Title</th><th>Affected file/package/path</th><th>Risk / description</th><th>Recommended action</th><th>Status</th></tr></thead>
      <tbody>
        ${ctx.findings.length ? ctx.findings.map((finding) => `<tr><td class="sev ${htmlEscape(finding.severity)}">${htmlEscape(finding.severity)}</td><td>${htmlEscape(finding.tool)}</td><td>${htmlEscape(finding.title)}</td><td>${htmlEscape(finding.affected)}</td><td>${htmlEscape(finding.risk)}</td><td>${htmlEscape(finding.action)}</td><td contenteditable="true">${htmlEscape(finding.status)}</td></tr>`).join('') : '<tr><td colspan="7" class="muted">No parsed findings. Missing tools are shown as Not run in the status cards.</td></tr>'}
      </tbody>
    </table>

    <h2>Manual Review Checklist</h2>
    <section class="checklist">${checklist.map((item) => `<div class="checkitem"><span class="box"></span><span>${htmlEscape(item)}</span></div>`).join('')}</section>

    <h2>Reviewer Notes</h2>
    <section class="recommendation" contenteditable="true">
      Add local review notes, owner assignments, accepted-risk rationale, or final approval details here.
    </section>
  </main>
</body>
</html>`;
}

function main() {
  const reportDir = resolveReportDir(process.argv[2]);
  const ctx = {
    reportDir,
    repoName: parseRepoName(reportDir),
    generatedAt: new Date().toISOString(),
    findings: [],
    tools: {},
    buildStatuses: {},
    summary: {},
  };
  parseGitleaks(ctx);
  parseBuildChecks(ctx);
  parseSemgrep(ctx);
  parseTrivy(ctx);
  parseOsv(ctx);
  parseCheckov(ctx);
  parseZap(ctx);
  parseAudit(ctx);
  parseAiReview(ctx);
  ctx.findings.sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity) || a.tool.localeCompare(b.tool));
  computeSummary(ctx);

  const output = path.join(reportDir, OUTPUT_NAME);
  fs.writeFileSync(output, render(ctx), 'utf8');
  console.log(`Security dashboard written: ${output}`);
  console.log(`Overall: ${statusLabel(ctx.summary.overall)} | Recommendation: ${ctx.summary.recommendation}`);
}

try {
  main();
} catch (error) {
  console.error(`ERROR: ${error.message}`);
  process.exit(1);
}
