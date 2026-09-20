'use strict';
const {runSafeExecutionFixture}=require('../cloud-sandbox/safe-execution-harness');
const ORIGIN='https://malguard.github.io';
module.exports=async function handler(req,res){
 res.setHeader('Cache-Control','no-store');res.setHeader('Content-Type','application/json; charset=utf-8');res.setHeader('Access-Control-Allow-Origin',ORIGIN);res.setHeader('Access-Control-Allow-Methods','POST, OPTIONS');res.setHeader('Vary','Origin');
 if(req.method==='OPTIONS')return res.status(204).end();
 if(req.method!=='POST'){res.setHeader('Allow','POST, OPTIONS');return res.status(405).json({ok:false,error:'method-not-allowed'})}
 try{const {Sandbox}=await import('@vercel/sandbox');return res.status(200).json(await runSafeExecutionFixture({Sandbox}))}
 catch(e){console.error('safe execution self-test failed:',e&&e.message);return res.status(503).json({ok:false,error:'safe-execution-self-test-failed'})}
};
