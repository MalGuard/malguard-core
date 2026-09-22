'use strict';

const assert=require('assert');

function responseHarness(){
  const state={status:200,headers:{},body:null};
  return {
    state,
    setHeader(k,v){state.headers[k]=v},
    status(n){state.status=n;return this},
    json(v){state.body=v;return this},
  };
}

(async()=>{
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
  const message=handler._test.emailText(parsed);
  assert(message.includes('New MalGuard installation'));
  assert(message.includes('CPU cores: 9-12'));
  assert.throws(()=>handler._test.parseBody({body:{...valid,extra:'not-allowed'}}));

  const oldFetch=global.fetch;
  const oldKey=process.env.RESEND_API_KEY;
  const oldTo=process.env.MALGUARD_INSTALL_NOTIFY_EMAIL;
  const oldFrom=process.env.MALGUARD_INSTALL_FROM_EMAIL;
  process.env.RESEND_API_KEY='test-key';
  process.env.MALGUARD_INSTALL_NOTIFY_EMAIL='owner@example.test';
  process.env.MALGUARD_INSTALL_FROM_EMAIL='MalGuard <notify@example.test>';

  let sent=null;
  global.fetch=async(url,options)=>{
    sent={url,body:JSON.parse(options.body)};
    return {ok:true,status:200};
  };
  const res=responseHarness();
  await handler({method:'POST',body:valid},res);
  assert.strictEqual(res.state.status,200);
  assert.strictEqual(res.state.body.ok,true);
  assert.strictEqual(sent.url,'https://api.resend.com/emails');
  assert.strictEqual(sent.body.to[0],'owner@example.test');
  assert(sent.body.text.includes('Windows build: 26100'));

  global.fetch=oldFetch;
  if(oldKey===undefined)delete process.env.RESEND_API_KEY;else process.env.RESEND_API_KEY=oldKey;
  if(oldTo===undefined)delete process.env.MALGUARD_INSTALL_NOTIFY_EMAIL;else process.env.MALGUARD_INSTALL_NOTIFY_EMAIL=oldTo;
  if(oldFrom===undefined)delete process.env.MALGUARD_INSTALL_FROM_EMAIL;else process.env.MALGUARD_INSTALL_FROM_EMAIL=oldFrom;

  console.log('✓ compatibility install email API');
})().catch(e=>{console.error(e);process.exit(1)});
