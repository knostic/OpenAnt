// The browser-smoke script (Playwright + a real Chromium): the CSP's first
// real-browser enforcement pass over the OpenAnt UI pages + /report, plus
// the golden render oracle for vendored marked/DOMPurify bumps.
//
// argv: node browser_smoke.mjs <baseURL> <goldenExpectedPath>
// env:  OPENANT_UPDATE_GOLDEN=1 re-captures the golden instead of comparing.
//
// FAILURE SEMANTICS (the consult's convergence): FAIL on any
// securitypolicyviolation; any pageerror; any same-origin response >= 400
// (except /favicon.ico); any same-origin requestfailed except
// net::ERR_ABORTED (the scan page's es.close() aborts its own SSE stream —
// page-initiated, never a CSP/network failure); any missing readiness; the
// canaries; the golden mismatch (in compare mode). The console handler
// also FAILs on "Refused to" text — Chromium logs every CSP block as a
// console error, so it is the backstop if the init-script listener ever
// silently fails to attach.
import { readFileSync, writeFileSync } from 'node:fs';
import { chromium } from 'playwright';

const [baseURL, goldenPath] = process.argv.slice(2);
if (!baseURL || !goldenPath) {
  console.error('usage: node browser_smoke.mjs <baseURL> <goldenExpectedPath>');
  process.exit(2);
}
const update = process.env.OPENANT_UPDATE_GOLDEN === '1';
const origin = new URL(baseURL).origin;

// OPENANT_BROWSER_CHANNEL=chrome drives the system-installed Chrome
// (a local convenience when the bundled-Chromium CDN download is slow);
// CI uses the default bundled chromium. Same engine family, same policy.
const launchOpts = process.env.OPENANT_BROWSER_CHANNEL
  ? { channel: process.env.OPENANT_BROWSER_CHANNEL }
  : {};
const browser = await chromium.launch(launchOpts);
const context = await browser.newContext();
// The violation listener BEFORE any navigation (context-level init script);
// addInitScript runs via CDP and is CSP-exempt — never addScriptTag.
await context.addInitScript(() => {
  window.__violations = [];
  window.addEventListener('securitypolicyviolation', (e) => {
    window.__violations.push(
      `${e.violatedDirective} blocked=${e.blockedURI} at ${(e.sourceFile || '')}:${e.lineNumber}`);
  });
});

const failures = [];
let violationsSeen = 0;
const note = (page, msg) => failures.push(`[${page}] ${msg}`);

async function visit(name, path) {
  const page = await context.newPage();
  page.setDefaultTimeout(10_000);
  page.on('pageerror', (e) => note(name, `pageerror: ${e.message}`));
  page.on('console', (m) => {
    if (m.type() === 'error' && m.text().includes('Refused to')) {
      // The known allowance, console channel: DOMPurify's self-test style
      // (see the drain) also logs 'Refused to apply inline style ...' here
      // on bundled Chromium builds (version-dependent emission — system
      // Chrome 152 logs only the event). The filter is NON-LOSSY: the
      // only inline styles on these pages are the nonced template styles
      // (never refused) and DOMPurify's probe (counted via the event
      // channel); a REAL inline-style leak from the markdown path would
      // trip the style= canary independently of this channel. Any other
      // 'Refused to' — inline script, load, connect — still fails.
      if (!m.text().includes('Refused to apply inline style')) {
        note(name, `console: ${m.text()}`);
      }
    }
  });
  page.on('response', (r) => {
    const u = new URL(r.url());
    if (u.origin === origin && r.status() >= 400 && !u.pathname.endsWith('favicon.ico')) {
      note(name, `HTTP ${r.status()} on ${u.pathname}`);
    }
  });
  page.on('requestfailed', (r) => {
    const u = new URL(r.url());
    if (u.origin === origin && !(r.failure()?.errorText || '').includes('ERR_ABORTED')) {
      note(name, `requestfailed: ${u.pathname} ${r.failure()?.errorText}`);
    }
  });
  const resp = await page.goto(baseURL + path, { waitUntil: 'networkidle' });
  // Zero violations alone does not prove enforcement — a missing policy also
  // passes. Assert the enforcing header on every navigation response.
  const csp = resp.headers()['content-security-policy'] || '';
  if (!csp.includes("default-src 'none'")) {
    note(name, `the navigation response carries no enforcing CSP: ${csp.slice(0, 90)}`);
  }
  return { page, csp };
}

const ready = async (page, name, fn) => { try { await fn(); } catch (e) { note(name, `readiness: ${e.message.split('\n')[0]}`); } };

// The violation DRAIN (the review round's catch): the init-script listener
// pushes into window.__violations — read it AFTER the async work settles
// (readiness + networkidle) and BEFORE page.close(), or the events die with
// the page. Without this the listener is dead code and enforcement rests
// only on the console-'Refused to' backstop.
const drain = async (page, name) => {
  const viols = await page.evaluate(() => window.__violations || []);
  for (const v of viols) {
    // The KNOWN allowance, and only this shape: DOMPurify 3.4.15's own
    // load-time self-test creates an inline <style> (reported as
    // style-src-elem blocked=inline sourced from the vendored blob) —
    // our style-src 'nonce' policy blocks it on every page load. The
    // empirical evidence the blocking is harmless to sanitization: the
    // golden matched and every canary clean WITH the probe blocked (the
    // entire prior verification stack — the 16-vector battery, the
    // jsdom differentials, the golden — ran under exactly this policy).
    // The filter is NARROW: style-src-elem sourced from the dompurify
    // ASSET only; any other style-src-elem — including one sourced from
    // the PAGE itself (an injected inline style surviving the markdown
    // path) — still fails.
    if (v.startsWith('style-src-elem') && v.includes('/assets/dompurify-')) {
      dompurifyProbeBlocked++;
      continue;
    }
    note(name, 'csp violation: ' + v);
    violationsSeen++;
  }
  return viols.length;
};
let dompurifyProbeBlocked = 0;

// --- / (index): the nonced inline script executed; NO click (accepting the
// delete confirm would destroy the seeded job for every later page).
{
  const { page } = await visit('index', '/');
  await ready(page, 'index', () => page.waitForFunction(() => typeof deleteScan === 'function'));
  const hasRows = await page.locator('#scans-list .scan-row').count();
  if (hasRows < 1) note('index', 'the seeded scan row is not rendered');
  await drain(page, 'index');
  await page.close();
}

// --- /scan/jx: the live page for a done job — the SSE done event + the
// post-done fetches are the only real connect-src 'self' exercise.
{
  const { page } = await visit('scan', '/scan/jx');
  await ready(page, 'scan', () => page.waitForSelector('#btn-summary.ready'));
  await ready(page, 'scan', () => page.waitForFunction(
    () => document.querySelectorAll('#disclosure-links a').length >= 1));
  await ready(page, 'scan', () => page.waitForFunction(
    () => !document.getElementById('status-text').textContent.includes('Scanning')));
  await drain(page, 'scan');
  await page.close();
}

// --- /summary/jx: the render path — readiness, the CANARIES (hard,
// --update-golden cannot touch them), then the golden.
let summaryHTML = '';
{
  const { page } = await visit('summary', '/summary/jx');
  await ready(page, 'summary', () => page.waitForFunction(
    () => document.getElementById('content').children.length >= 1
      && document.getElementById('content').textContent.trim().length > 0
      && !document.getElementById('content').textContent.includes('Loading')));
  summaryHTML = await page.$eval('#content', (el) => el.innerHTML);

  const ABSENT = ['<img', '<form', '<input', '<style', '<script', 'javascript:',
    ' href="data:', ' src="data:', 'style=', 'src=', 'onerror', 'onclick'];
  const PRESENT = ['<table', '<strong>Repository:</strong>', '<code>',
    '<a href="https://example.com/docs"', 'unchecked task', 'completed task'];
  for (const bad of ABSENT) {
    if (summaryHTML.toLowerCase().includes(bad)) note('summary', `canary ABSENT failed: ${bad} reached the DOM`);
  }
  for (const good of PRESENT) {
    if (!summaryHTML.includes(good)) note('summary', `canary PRESENT failed: ${good} missing from the DOM`);
  }
  await drain(page, 'summary');
  await page.close();
}

// --- /disclosure/jx/d.md: the same render path on the second channel.
{
  const { page } = await visit('disclosure', '/disclosure/jx/d.md');
  await ready(page, 'disclosure', () => page.waitForFunction(
    () => document.getElementById('content').children.length >= 1
      && !document.getElementById('content').textContent.includes('Loading')));
  await drain(page, 'disclosure');
  await page.close();
}

// --- /report/jx: a REAL generated report (report.GenerateReskin) — the
// runtime proof that Chart.js + datalabels run INLINE under script-src
// 'unsafe-inline' with no unsafe-eval (the header assertion csp_test
// deliberately declines to make).
{
  const { page } = await visit('report', '/report/jx');
  await ready(page, 'report', () => page.waitForFunction(() => typeof Chart === 'function'));
  await ready(page, 'report', () => page.waitForSelector('#unitChart'));
  await drain(page, 'report');
  await page.close();
}

if (update && failures.length === 0) {
  writeFileSync(goldenPath, summaryHTML + '\n');
  console.log('GOLDEN UPDATED: ' + goldenPath);
} else if (update) {
  note('summary', 'update mode declined: the run had failures (the golden was NOT clobbered)');
} else {
  const expected = readFileSync(goldenPath, 'utf8');
  if (summaryHTML + '\n' !== expected && summaryHTML !== expected.trim()) {
    note('summary', 'golden mismatch — ACTUAL #content innerHTML follows:');
    console.log('--- ACTUAL #content innerHTML ---');
    console.log(summaryHTML);
    console.log('--- END ACTUAL ---');
  }
}

await browser.close();

// Late violations from any page (the listener ran in every page).
// Re-check: the pages are closed; violations were per-page. We aggregate
// them at close time by reading before close — done implicitly above via
// the per-page note path. Any __violations content was already collected.

if (failures.length > 0) {
  console.error('BROWSER-SMOKE FAILURES (' + failures.length + '):');
  for (const f of failures) console.error('  ' + f);
  process.exit(1);
}
console.log(`BROWSER-SMOKE OK: 5 pages, ${violationsSeen} unexpected violations` +
  ` (+${dompurifyProbeBlocked} known-blocked DOMPurify self-test styles), canaries clean` +
  (update ? '' : ', golden matched'));
