'use strict';

const fs = require('fs');
const path = require('path');

const appRoot = path.resolve(__dirname, '..');
const source = path.resolve(process.argv[2] || '');
if (!process.argv[2] || !fs.existsSync(source)) {
  throw new Error('Usage: node app-shell/scripts/prepare-offline-site.js <site-root>');
}

const lock = JSON.parse(fs.readFileSync(path.join(appRoot, 'site-lock.json'), 'utf8'));
const destinations = [
  path.join(appRoot, 'mobile', 'www'),
  path.join(appRoot, 'desktop', 'www')
];

const files = [
  'index.html','404.html','tools.html','trust.html','privacy.html','support.html',
  'about.html','labs.html','docs.html','download.html','scan-mods.html',
  'ai-intelligence.html','scan-url.html','products.html','gta-guard.html','app.html',
  'robots.txt','sitemap.xml','favicon.ico','favicon-96.png','favicon-192.png',
  '.well-known/security.txt'
];
const dirs = ['assets','downloads','ios-preview','research'];

function copyFile(rel,dest){
  const from=path.join(source,rel),to=path.join(dest,rel);
  if(!fs.existsSync(from)||!fs.statSync(from).isFile()) throw new Error('Missing production file: '+rel);
  fs.mkdirSync(path.dirname(to),{recursive:true});
  fs.copyFileSync(from,to);
}
function copyDir(rel,dest){
  const from=path.join(source,rel),to=path.join(dest,rel);
  if(!fs.existsSync(from)||!fs.statSync(from).isDirectory()) throw new Error('Missing production directory: '+rel);
  fs.cpSync(from,to,{recursive:true});
}
function patchIndex(dest){
  const p=path.join(dest,'index.html');
  let s=fs.readFileSync(p,'utf8');
  s=s.replace(/url\(["']https:\/\/assets\.science\.nasa\.gov\/[^"')]+["']\)/g,'url("/assets/malguard-earth-background.png")');
  s=s.replace(/url\(["']https:\/\/cdn\.creativeclaw\.co\/[^"')]+["']\)/g,'url("/assets/malguard-earth-background.png")');
  fs.writeFileSync(p,s);
}
function verify(dest){
  const required=[
    'index.html','app.html','download.html','scan-mods.html','ai-intelligence.html',
    'scan-url.html','products.html','gta-guard.html','assets/pro-polish.css',
    'assets/site-pages.css','assets/malguard-site-logo.svg','assets/malguard-earth-background.png'
  ];
  for(const rel of required) if(!fs.existsSync(path.join(dest,rel))) throw new Error('Offline bundle missing: '+rel);

  const check=[];
  const walk=d=>{for(const e of fs.readdirSync(d,{withFileTypes:true})){const p=path.join(d,e.name);if(e.isDirectory())walk(p);else if(/\.(?:html|css|js)$/i.test(e.name))check.push(p)}};
  walk(dest);
  for(const p of check){
    const s=fs.readFileSync(p,'utf8');
    if(/<script\b[^>]*\bsrc=["']https?:\/\//i.test(s)) throw new Error('Remote script dependency: '+path.relative(dest,p));
    if(/url\(\s*["']?https?:\/\//i.test(s)) throw new Error('Remote CSS/image dependency: '+path.relative(dest,p));
  }
  if(!fs.readFileSync(path.join(dest,'index.html'),'utf8').includes('/assets/malguard-earth-background.png')){
    throw new Error('Offline Earth image replacement did not apply');
  }
}

for(const dest of destinations){
  fs.rmSync(dest,{recursive:true,force:true});
  fs.mkdirSync(dest,{recursive:true});
  for(const rel of files)copyFile(rel,dest);
  for(const rel of dirs)copyDir(rel,dest);
  patchIndex(dest);
  verify(dest);
}
fs.writeFileSync(path.join(appRoot,'OFFLINE-SOURCE.json'),JSON.stringify(lock,null,2)+'\n');
console.log('Offline MalGuard bundle prepared from '+lock.repository+'@'+lock.commit);
