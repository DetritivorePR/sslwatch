#!/usr/bin/env node
/**
 * sslwatch — SSL certificate expiry monitor with Slack/email alerts
 * Usage: node src/sslwatch.js <command> [options]
 */

'use strict';

const https  = require('https');
const tls    = require('tls');
const fs     = require('fs');
const path   = require('path');

const BOLD   = '\x1b[1m';
const GREEN  = '\x1b[32m';
const YELLOW = '\x1b[33m';
const RED    = '\x1b[31m';
const CYAN   = '\x1b[36m';
const DIM    = '\x1b[2m';
const NC     = '\x1b[0m';

const CONFIG_FILE = 'sslwatch.config.json';
const HISTORY_FILE = '.sslwatch-history.json';

// ── Config helpers ────────────────────────────────────────────────────────────
function defaultConfig() {
  return {
    hosts: [],
    alertDaysWarning: 30,
    alertDaysCritical: 7,
    slack: { webhookUrl: '', enabled: false },
    email: { to: '', from: '', smtpHost: '', smtpPort: 587, enabled: false },
    checkIntervalHours: 24,
  };
}

function loadConfig() {
  if (!fs.existsSync(CONFIG_FILE)) return defaultConfig();
  try { return { ...defaultConfig(), ...JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8')) }; }
  catch { return defaultConfig(); }
}

function loadHistory() {
  if (!fs.existsSync(HISTORY_FILE)) return {};
  try { return JSON.parse(fs.readFileSync(HISTORY_FILE, 'utf8')); }
  catch { return {}; }
}

function saveHistory(h) { fs.writeFileSync(HISTORY_FILE, JSON.stringify(h, null, 2)); }

// ── SSL check ─────────────────────────────────────────────────────────────────
function checkCert(hostname, port = 443, timeoutMs = 10000) {
  return new Promise((resolve) => {
    const result = { hostname, port, checked: new Date().toISOString(), error: null, cert: null, daysRemaining: null, status: 'unknown' };

    const socket = tls.connect({ host: hostname, port, servername: hostname, rejectUnauthorized: false }, () => {
      try {
        const cert = socket.getPeerCertificate();
        socket.destroy();

        if (!cert || !cert.valid_to) {
          result.error = 'No certificate returned';
          result.status = 'error';
          return resolve(result);
        }

        const expiry = new Date(cert.valid_to);
        const now    = new Date();
        const days   = Math.floor((expiry - now) / (1000 * 60 * 60 * 24));

        result.cert = {
          subject:   cert.subject && cert.subject.CN ? cert.subject.CN : hostname,
          issuer:    cert.issuer && cert.issuer.O ? cert.issuer.O : 'Unknown',
          validFrom: cert.valid_from,
          validTo:   cert.valid_to,
          fingerprint: cert.fingerprint || '',
          subjectAltNames: cert.subjectaltname || '',
        };
        result.daysRemaining = days;
        result.status = days < 0 ? 'expired' : days < 7 ? 'critical' : days < 30 ? 'warning' : 'ok';
        resolve(result);
      } catch (e) {
        socket.destroy();
        result.error = e.message;
        result.status = 'error';
        resolve(result);
      }
    });

    socket.setTimeout(timeoutMs, () => {
      socket.destroy();
      result.error = `Connection timed out after ${timeoutMs / 1000}s`;
      result.status = 'error';
      resolve(result);
    });

    socket.on('error', (e) => {
      result.error = e.message;
      result.status = 'error';
      resolve(result);
    });
  });
}

// ── Slack alert ───────────────────────────────────────────────────────────────
function sendSlackAlert(webhookUrl, message) {
  return new Promise((resolve) => {
    if (!webhookUrl) { resolve({ ok: false, reason: 'No webhook URL configured' }); return; }

    const url = new URL(webhookUrl);
    const body = JSON.stringify({ text: message });
    const req  = https.request({
      hostname: url.hostname,
      path:     url.pathname + url.search,
      method:   'POST',
      headers:  { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
    }, (res) => {
      res.resume();
      resolve({ ok: res.statusCode === 200 });
    });
    req.on('error', (e) => resolve({ ok: false, reason: e.message }));
    req.write(body);
    req.end();
  });
}

function buildAlertMessage(results, config) {
  const critical = results.filter(r => r.status === 'critical' || r.status === 'expired');
  const warning  = results.filter(r => r.status === 'warning');

  if (critical.length === 0 && warning.length === 0) return null;

  let msg = `🔐 *SSLWatch Alert*\n`;
  if (critical.length > 0) {
    msg += `\n🚨 *CRITICAL / EXPIRED:*\n`;
    critical.forEach(r => {
      msg += r.status === 'expired'
        ? `• \`${r.hostname}\` — ❌ EXPIRED ${Math.abs(r.daysRemaining)} days ago\n`
        : `• \`${r.hostname}\` — ⚠️ Expires in ${r.daysRemaining} days\n`;
    });
  }
  if (warning.length > 0) {
    msg += `\n⚠️ *WARNING:*\n`;
    warning.forEach(r => msg += `• \`${r.hostname}\` — Expires in ${r.daysRemaining} days (${r.cert ? r.cert.validTo : '?'})\n`);
  }
  return msg;
}

// ── Commands ──────────────────────────────────────────────────────────────────
async function checkCommand(hosts, opts = {}) {
  const config = loadConfig();
  const targetHosts = hosts.length > 0 ? hosts : config.hosts;

  if (targetHosts.length === 0) {
    console.log(`${YELLOW}⚠️  No hosts specified. Add hosts:${NC}`);
    console.log('  node src/sslwatch.js add example.com');
    console.log('  node src/sslwatch.js check example.com github.com');
    return;
  }

  console.log(`\n${BOLD}${CYAN}🔐 SSLWatch — Certificate Check${NC}`);
  console.log(`Checking ${targetHosts.length} host(s)...\n`);

  const results = [];
  for (const h of targetHosts) {
    const [hostname, portStr] = h.split(':');
    const port = portStr ? parseInt(portStr) : 443;
    process.stdout.write(`  Checking ${hostname}:${port}... `);
    const r = await checkCert(hostname, port);
    results.push(r);

    if (r.error) {
      console.log(`${RED}ERROR${NC} — ${r.error}`);
    } else {
      const col = r.status === 'ok' ? GREEN : r.status === 'warning' ? YELLOW : RED;
      const icon = r.status === 'ok' ? '✅' : r.status === 'warning' ? '⚠️ ' : r.status === 'expired' ? '❌' : '🚨';
      console.log(`${col}${icon} ${r.daysRemaining} days${NC}  (expires ${r.cert.validTo})`);
    }
  }

  console.log('');
  const ok       = results.filter(r => r.status === 'ok').length;
  const warning  = results.filter(r => r.status === 'warning').length;
  const critical = results.filter(r => r.status === 'critical').length;
  const expired  = results.filter(r => r.status === 'expired').length;
  const error    = results.filter(r => r.status === 'error').length;

  console.log('─'.repeat(50));
  console.log(`${BOLD}OK: ${ok}  Warning: ${warning}  Critical: ${critical}  Expired: ${expired}  Error: ${error}${NC}`);

  // Save history
  const history = loadHistory();
  for (const r of results) {
    if (!history[r.hostname]) history[r.hostname] = [];
    history[r.hostname].push({ timestamp: r.checked, daysRemaining: r.daysRemaining, status: r.status });
    history[r.hostname] = history[r.hostname].slice(-30); // keep last 30 checks
  }
  saveHistory(history);

  // Send Slack alert if configured
  if (config.slack.enabled && config.slack.webhookUrl) {
    const msg = buildAlertMessage(results, config);
    if (msg) {
      process.stdout.write('\n📨 Sending Slack alert... ');
      const res = await sendSlackAlert(config.slack.webhookUrl, msg);
      console.log(res.ok ? `${GREEN}sent${NC}` : `${RED}failed — ${res.reason}${NC}`);
    }
  }

  if (opts.output) {
    fs.writeFileSync(opts.output, JSON.stringify({ checkedAt: new Date().toISOString(), results }, null, 2));
    console.log(`\n📄 Report saved: ${opts.output}`);
  }
}

function addCommand(hostList) {
  const config = loadConfig();
  const added = [];
  for (const h of hostList) {
    if (!config.hosts.includes(h)) { config.hosts.push(h); added.push(h); }
  }
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2));
  if (added.length > 0) console.log(`${GREEN}✅ Added: ${added.join(', ')}${NC}`);
  else console.log(`${YELLOW}ℹ️  All hosts already in watchlist${NC}`);
  console.log(`Watchlist: ${config.hosts.join(', ')}`);
}

function removeCommand(hostList) {
  const config = loadConfig();
  config.hosts = config.hosts.filter(h => !hostList.includes(h));
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2));
  console.log(`${GREEN}✅ Removed: ${hostList.join(', ')}${NC}`);
  console.log(`Watchlist: ${config.hosts.join(', ') || '(empty)'}`);
}

function listCommand() {
  const config  = loadConfig();
  const history = loadHistory();

  console.log(`\n${BOLD}${CYAN}🔐 SSLWatch — Watchlist${NC}\n`);

  if (config.hosts.length === 0) {
    console.log('No hosts in watchlist. Add with: node src/sslwatch.js add example.com');
    return;
  }

  config.hosts.forEach(h => {
    const hist = history[h.split(':')[0]] || [];
    const last = hist[hist.length - 1];
    if (last) {
      const col = last.status === 'ok' ? GREEN : last.status === 'warning' ? YELLOW : RED;
      console.log(`  ${col}${h}${NC}  ${last.daysRemaining} days remaining  ${DIM}(${last.timestamp.slice(0,10)})${NC}`);
    } else {
      console.log(`  ${DIM}${h}  (not yet checked)${NC}`);
    }
  });
  console.log('');
}

function configCommand(opts = {}) {
  if (opts.show) {
    const config = loadConfig();
    console.log(JSON.stringify(config, null, 2));
    return;
  }
  if (opts.slackWebhook) {
    const config = loadConfig();
    config.slack.webhookUrl = opts.slackWebhook;
    config.slack.enabled    = true;
    fs.writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2));
    console.log(`${GREEN}✅ Slack webhook configured${NC}`);
    return;
  }
  if (!fs.existsSync(CONFIG_FILE)) {
    fs.writeFileSync(CONFIG_FILE, JSON.stringify(defaultConfig(), null, 2));
    console.log(`${GREEN}✅ Created sslwatch.config.json${NC}`);
    console.log(`Edit it to add hosts, Slack webhook, alert thresholds, etc.`);
  } else {
    console.log(`Config already exists at ${CONFIG_FILE}`);
  }
}

async function watchCommand(intervalHours, opts = {}) {
  const config = loadConfig();
  const interval = (parseFloat(intervalHours) || config.checkIntervalHours || 24) * 60 * 60 * 1000;

  console.log(`\n${BOLD}${CYAN}👁️  SSLWatch — Watch Mode${NC}`);
  console.log(`Checking every ${interval / 3600000}h | Hosts: ${config.hosts.join(', ')}`);
  console.log('Press Ctrl+C to stop.\n');

  const run = () => checkCommand([], opts);
  await run();
  setInterval(run, interval);
}

// ── CLI ───────────────────────────────────────────────────────────────────────
const [,, cmd, ...rest] = process.argv;

if (!cmd || cmd === 'help') {
  console.log('sslwatch — SSL Certificate Expiry Monitor\n');
  console.log('Commands:');
  console.log('  check [host1 host2...]       Check SSL certs (uses watchlist if no hosts given)');
  console.log('  check --out report.json      Save results to JSON');
  console.log('  add <host1> [host2...]        Add hosts to watchlist');
  console.log('  remove <host1> [host2...]     Remove hosts from watchlist');
  console.log('  list                          Show watchlist with last check results');
  console.log('  config                        Create/show config file');
  console.log('  config --slack-webhook <url>  Set Slack webhook URL');
  console.log('  watch [interval-hours]        Continuous watch mode');
  console.log('\nExamples:');
  console.log('  node src/sslwatch.js check github.com google.com');
  console.log('  node src/sslwatch.js add github.com api.example.com:8443');
  console.log('  node src/sslwatch.js watch 6');
  process.exit(0);
}

(async () => {
  if (cmd === 'check') {
    const outIdx = rest.indexOf('--out');
    const output = outIdx !== -1 ? rest.splice(outIdx, 2)[1] : null;
    await checkCommand(rest, { output });
  } else if (cmd === 'add') {
    addCommand(rest);
  } else if (cmd === 'remove') {
    removeCommand(rest);
  } else if (cmd === 'list') {
    listCommand();
  } else if (cmd === 'config') {
    const slackIdx = rest.indexOf('--slack-webhook');
    configCommand({
      show: rest.includes('--show'),
      slackWebhook: slackIdx !== -1 ? rest[slackIdx + 1] : null,
    });
  } else if (cmd === 'watch') {
    const outIdx = rest.indexOf('--out');
    const output = outIdx !== -1 ? rest[outIdx + 1] : null;
    await watchCommand(rest[0], { output });
  } else {
    console.error(`Unknown command: ${cmd}`); process.exit(1);
  }
})();
