# 🔒 sslwatch

[![CI](https://github.com/YOUR_USERNAME/sslwatch/actions/workflows/ci.yml/badge.svg)](https://github.com/YOUR_USERNAME/sslwatch/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/Node.js-20+-green.svg)](https://nodejs.org)
[![GitHub Achievements](https://img.shields.io/badge/GitHub-Achievements-blueviolet.svg)](https://github.com/YOUR_USERNAME)

> SSL certificate expiry monitor with Slack alerts — never let a certificate silently expire again.

## ✨ Features

- 🔍 Check SSL cert expiry for any HTTPS host (real TLS handshake, no external APIs needed)
- 📊 Status levels: OK / WARNING (< 30 days) / CRITICAL (< 7 days) / EXPIRED
- 📢 Slack webhook alerts for critical and warning certs
- 👁️ Watch mode — continuous monitoring at configurable intervals
- 📋 Persistent watchlist and check history in local JSON store
- 💾 JSON report export for CI integration

## 🚀 Quick Start

```bash
npm install
node src/sslwatch.js check github.com google.com
node src/sslwatch.js add mysite.com api.mysite.com
node src/sslwatch.js check
```

## 📖 Usage

```bash
node src/sslwatch.js check [host1 host2...]
node src/sslwatch.js add <host1> [host2...]
node src/sslwatch.js remove <host>
node src/sslwatch.js list
node src/sslwatch.js config --slack-webhook <url>
node src/sslwatch.js watch [interval-hours]
```

## 🏆 Achievement Scripts

```bash
bash scripts/setup.sh
bash scripts/unlock-all.sh
```
