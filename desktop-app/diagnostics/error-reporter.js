'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

const MAX_REPORTS = 100;

function defaultReportRoot() {
  const base = process.platform === 'win32'
    ? (process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local'))
    : path.join(os.homedir(), '.config');
  return path.join(base, 'MalGuard', 'diagnostics');
}

function safeText(value, max = 2048) {
  return String(value == null ? '' : value)
    .replace(/[\r\n\t]+/g, ' ')
    .replace(/(?:[A-Za-z]:\\|\/)[^ ]+/g, '[path]')
    .replace(/(?:Bearer\s+)?[A-Za-z0-9_-]{24,}/g, '[redacted]')
    .slice(0, max);
}

class LocalErrorReporter {
  constructor(root = process.env.MALGUARD_DIAGNOSTICS_ROOT || defaultReportRoot()) {
    this.root = path.resolve(root);
  }

  async record(error, context = {}) {
    await fs.promises.mkdir(this.root, { recursive: true, mode: 0o700 });
    const report = {
      schemaVersion: '1.0.0',
      id: crypto.randomUUID(),
      time: new Date().toISOString(),
      code: safeText(error && error.code ? error.code : 'INTERNAL_ERROR', 128),
      name: safeText(error && error.name ? error.name : 'Error', 128),
      message: safeText(error && error.message ? error.message : 'internal error'),
      context: {
        area: safeText(context.area || 'runtime', 128),
        method: safeText(context.method || '', 16),
        route: safeText(context.route || '', 256),
      },
      runtime: { node: process.version, platform: process.platform, arch: process.arch },
    };
    const file = path.join(this.root, `${report.time.replace(/[:.]/g, '-')}-${report.id}.json`);
    await fs.promises.writeFile(file, JSON.stringify(report, null, 2), { encoding: 'utf8', mode: 0o600, flag: 'wx' });
    await this.prune();
    return report;
  }

  async prune() {
    const entries = (await fs.promises.readdir(this.root)).filter(name => name.endsWith('.json')).sort().reverse();
    await Promise.all(entries.slice(MAX_REPORTS).map(name => fs.promises.rm(path.join(this.root, name), { force: true })));
  }

  async list(limit = 20) {
    try {
      const entries = (await fs.promises.readdir(this.root)).filter(name => name.endsWith('.json')).sort().reverse().slice(0, Math.max(1, Math.min(100, Number(limit) || 20)));
      const reports = [];
      for (const name of entries) {
        try { reports.push(JSON.parse(await fs.promises.readFile(path.join(this.root, name), 'utf8'))); } catch (_) {}
      }
      return reports;
    } catch (error) {
      if (error.code === 'ENOENT') return [];
      throw error;
    }
  }
}

module.exports = { LocalErrorReporter, safeText, defaultReportRoot, MAX_REPORTS };
