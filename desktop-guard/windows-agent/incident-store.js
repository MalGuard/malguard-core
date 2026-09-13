'use strict';

const fs = require('fs');
const path = require('path');
const { normalizeAbsolute } = require('./path-guard.js');

class IncidentStore {
  constructor(rootPath, options = {}) {
    this.rootPath = normalizeAbsolute(rootPath);
    this.eventsDir = path.join(this.rootPath, 'incidents');
    this.eventsFile = path.join(this.eventsDir, 'events.jsonl');
    this.maxReadBytes = Math.max(64 * 1024, Number(options.maxReadBytes) || 4 * 1024 * 1024);
  }

  async init() {
    await fs.promises.mkdir(this.eventsDir, { recursive: true });
  }

  _normalizeReport(report) {
    if (!report || typeof report !== 'object') throw new TypeError('incident report required');
    const out = {
      schemaVersion: String(report.schemaVersion || '1.0.0'),
      incidentId: String(report.incidentId || ''),
      modName: String(report.modName || 'Unknown mod'),
      responsibleFile: String(report.responsibleFile || 'Unknown file'),
      verdict: String(report.verdict || 'INCONCLUSIVE'),
      reason: String(report.reason || 'unspecified'),
      action: String(report.action || 'hold'),
      timestamp: Number.isFinite(report.timestamp) && report.timestamp > 0 ? report.timestamp : Date.now(),
      source: String(report.source || 'desktop-guard'),
    };
    if (!out.incidentId || out.incidentId.length > 256) {
      const error = new Error('invalid incident id');
      error.code = 'INVALID_INCIDENT_ID';
      throw error;
    }
    // Bound attacker-controlled strings so a malicious filename/reason cannot turn
    // the append-only audit log into an uncontrolled disk-growth primitive.
    for (const key of ['modName', 'responsibleFile', 'reason', 'source']) {
      if (out[key].length > 4096) out[key] = out[key].slice(0, 4096);
    }
    return out;
  }

  async append(report) {
    await this.init();
    const normalized = this._normalizeReport(report);
    const line = Buffer.from(JSON.stringify(normalized) + '\n', 'utf8');
    const handle = await fs.promises.open(this.eventsFile, 'a', 0o600);
    try {
      await handle.write(line, 0, line.length, null);
      await handle.sync();
    } finally {
      await handle.close();
    }
    return normalized;
  }

  async list(limit = 100) {
    await this.init();
    const capped = Math.max(1, Math.min(1000, Number(limit) || 100));
    let stat;
    try { stat = await fs.promises.stat(this.eventsFile); } catch (error) {
      if (error && error.code === 'ENOENT') return [];
      throw error;
    }
    const start = Math.max(0, stat.size - this.maxReadBytes);
    const handle = await fs.promises.open(this.eventsFile, 'r');
    try {
      const length = stat.size - start;
      const buffer = Buffer.alloc(length);
      if (length) await handle.read(buffer, 0, length, start);
      let text = buffer.toString('utf8');
      if (start > 0) {
        const newline = text.indexOf('\n');
        text = newline >= 0 ? text.slice(newline + 1) : '';
      }
      const rows = [];
      for (const line of text.split('\n')) {
        if (!line.trim()) continue;
        try { rows.push(JSON.parse(line)); } catch (_) { /* tolerate a torn/corrupt historic line */ }
      }
      return rows.slice(-capped).reverse();
    } finally {
      await handle.close();
    }
  }
}

module.exports = { IncidentStore };
