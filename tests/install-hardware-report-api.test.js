'use strict';
const assert=require('assert');
const handler=require('../api/install-hardware-report');
(async()=>{
 let code;let calls=0;const original=global.fetch;global.fetch=()=>{calls++;throw Error('legacy email must never send');};
 try {await handler({method:'POST',body:{}},{setHeader(){},status(n){code=n;return this;},json(x){return x;}});assert.equal(code,410);assert.equal(calls,0);}
 finally {global.fetch=original;}
 console.log('Legacy hardware/email endpoint retired: HTTP 410 and zero emails');
})().catch(e=>{console.error(e);process.exit(1);});
