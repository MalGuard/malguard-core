'use strict';

const assert=require('assert');
const {
  bucketCpuCores,bucketRam,windowsBuild,collectCompatibilityProfile
}=require('../desktop-app/metrics/compatibility-install-report.js');

const osImpl={
  cpus:()=>Array.from({length:12},()=>({})),
  totalmem:()=>24*(1024**3),
  release:()=> '10.0.26100',
};

assert.strictEqual(bucketCpuCores(12),'9-12');
assert.strictEqual(bucketRam(24*(1024**3)),'16-32 GB');
assert.strictEqual(windowsBuild('10.0.26100'),'26100');

const profile=collectCompatibilityProfile({
  platform:'win32',
  version:'0.6.1-beta.1',
  arch:'x64',
  osImpl,
  language:'en-US',
});

assert.deepStrictEqual(profile,{
  schemaVersion:'1.0',
  event:'first_successful_launch',
  version:'0.6.1-beta.1',
  os:'Windows',
  build:'26100',
  arch:'x64',
  cpuCoresBucket:'9-12',
  ramBucket:'16-32 GB',
  language:'en-US',
});

assert.deepStrictEqual(Object.keys(profile).sort(),[
  'arch','build','cpuCoresBucket','event','language','os','ramBucket','schemaVersion','version'
].sort());

console.log('✓ anonymous compatibility profile is coarse and allowlisted');
