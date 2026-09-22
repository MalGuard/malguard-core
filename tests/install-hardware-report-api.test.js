'use strict';

const assert=require('assert');
const handler=require('../api/install-hardware-report.js');

const valid={
  schemaVersion:'1.0',
  event:'first_successful_launch',
  version:'0.6.1-beta.1',
  os:'Windows',
  build:'26100',
  arch:'x64',
  cpuCoresBucket:'9-12',
  ramBucket:'16-32 GB',
  language:'en-US',
};

const parsed=handler._test.parseBody({body:valid});
assert.strictEqual(parsed.arch,'x64');
assert.strictEqual(parsed.build,'26100');
assert.throws(()=>handler._test.parseBody({body:{...valid,unexpected:'x'}}));

const message=handler._test.emailText(parsed);
assert(message.includes('New MalGuard installation'));
assert(message.includes('Windows build: 26100'));
assert(message.includes('CPU cores: 9-12'));
assert(message.includes('RAM: 16-32 GB'));

console.log('✓ compatibility install email payload validation');
