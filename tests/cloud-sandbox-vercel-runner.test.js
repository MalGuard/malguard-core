'use strict';
const assert=require('assert');
const crypto=require('crypto');
const {runSafeFixture}=require('../cloud-sandbox/vercel-runner');

let stopped=false, created=null;
class FakeSandbox {
  static async create(opts){ created=opts; return new FakeSandbox(); }
  async writeFiles(files){ this.data=files[0].content; }
  async runCommand(){
    const b=this.data;
    return {stdout:async()=>JSON.stringify({bytes:b.length,sha256:crypto.createHash('sha256').update(b).digest('hex'),marker:b.toString('utf8').trim()})};
  }
  async stop(){ stopped=true; }
}
(async()=>{
 const r=await runSafeFixture({Sandbox:FakeSandbox});
 assert.equal(r.ok,true);
 assert.equal(created.networkPolicy,'deny-all');
 assert.equal(created.persistent,false);
 assert.equal(created.timeout,30000);
 assert.equal(stopped,true);
 console.log('✓ Cloud Sandbox Vercel runner: ephemeral deny-all safe-fixture execution and teardown PASS');
})().catch(e=>{console.error(e);process.exit(1)});
