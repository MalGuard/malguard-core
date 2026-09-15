'use strict';

if (process.env.MALGUARD_SYNTHETIC_PROBE !== '1') process.exit(2);
const before = process.memoryUsage().rss;
const data = Buffer.alloc(128 * 1024, 0x4d);
const after = process.memoryUsage().rss;
if (process.send) {
  process.send({
    ok: data.length === 128 * 1024,
    probe: 'malguard-synthetic-isolation',
    pid: process.pid,
    rssDelta: Math.max(0, after - before),
  });
}
setTimeout(() => process.exit(0), 5);
