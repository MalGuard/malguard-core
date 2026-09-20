'use strict';
const {strictBase64,runBenignBehaviorTelemetry}=require('../cloud-sandbox/benign-behavior-telemetry');
const ORIGIN='https://malguard.github.io';
module.exports=async function handler(req,res){
 res.setHeader('Cache-Control','no-store');res.setHeader('Content-Type','application/json; charset=utf-8');res.setHeader('Access-Control-Allow-Origin',ORIGIN);res.setHeader('Access-Control-Allow-Headers','Content-Type');res.setHeader('Access-Control-Allow-Methods','POST, OPTIONS');res.setHeader('Vary','Origin');
 if(req.method==='OPTIONS')return res.status(204).end();
 if(req.method!=='POST'){res.setHeader('Allow','POST, OPTIONS');return res.status(405).json({ok:false,error:'method-not-allowed'})}
 try{
  const body=typeof req.body==='string'?JSON.parse(req.body):req.body;
  if(!body||Object.keys(body).some(k=>k!=='data'))return res.status(400).json({ok:false,error:'unsupported-input'});
  const data=strictBase64(body.data);if(!data)return res.status(400).json({ok:false,error:'invalid-file'});
  const {Sandbox}=await import('@vercel/sandbox');
  return res.status(200).json(await runBenignBehaviorTelemetry({Sandbox,data}));
 }catch(e){
  const policy=e&&['upload-not-allowlisted','invalid-upload'].includes(e.message);
  console.error('benign behavior telemetry failed:',e&&e.message);
  return res.status(policy?403:503).json({ok:false,error:policy?'execution-not-allowlisted':'behavior-telemetry-failed'});
 }
};
