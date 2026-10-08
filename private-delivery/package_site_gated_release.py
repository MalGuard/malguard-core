"""Verify the tested build, then publish only password-authenticated ciphertext.

The generated download code stays in a mode-0600 local vault. No installer,
password, derived key or device identifier is committed to the website.
"""
import base64
import hashlib
import json
import os
import re
import struct
import xml.etree.ElementTree as ET
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

VAULT=Path('/workspace/.private-malguard-1.3/site-gated-1.3.1')
ARTIFACTS=Path('/workspace/malguard-core/build/site-gated-delivery')
SITE=Path('/workspace/malguard.github.io')

def main():
    meta=json.loads((ARTIFACTS/'site-gated-release.json').read_text(encoding='utf-8-sig'))
    status=json.loads((ARTIFACTS/'build-status.json').read_text(encoding='utf-8-sig'))
    assert meta['status']=='site-gated-windows-build-verified'
    assert meta['app_version']=='1.3.1' and meta['engine_version']=='1.2.1'
    assert re.fullmatch('[a-f0-9]{40}',meta['source_commit'])
    assert meta['requires_device_license'] is False and meta['installer_password_required'] is False
    assert status['result']=='success' and status['source_commit']==meta['source_commit'] and status['run_id']==meta['run_id']
    qa=json.loads((ARTIFACTS/'gui-install-qa.json').read_text(encoding='utf-8-sig'))
    deadlines=json.loads((ARTIFACTS/'setup-deadline-qa.json').read_text(encoding='utf-8-sig'))
    assert qa['failed']==0 and qa['passed']==16 and deadlines['failed']==0 and deadlines['passed']==5
    online=next(c for c in qa['checks'] if c['name']=='installed-signed-online-feed')
    fixtures=next(c for c in qa['checks'] if c['name']=='installed-static-detection-and-bilingual-reports')
    assert online['passed'] is True and online['record_count']>0 and fixtures['fixtures']>=6
    xml=ET.parse(ARTIFACTS/'windows-tests.xml').getroot()
    suites=[xml] if xml.tag=='testsuite' else list(xml)
    passed=sum(int(s.attrib['tests'])-int(s.attrib.get('skipped',0)) for s in suites)
    skipped=sum(int(s.attrib.get('skipped',0)) for s in suites)
    assert passed>=1005 and all(int(s.attrib.get('failures',0))==0 and int(s.attrib.get('errors',0))==0 for s in suites)
    sealed=(ARTIFACTS/'MalGuard-Setup-x64.exe.sealed').read_bytes()
    assert hashlib.sha256(sealed).hexdigest()==meta['sealed_sha256'] and sealed[:8]==b'MGBUILD2'
    root=VAULT.parent
    private=serialization.load_pem_private_key((root/'delivery.pem').read_bytes(),(root/'vault-password').read_bytes())
    n=struct.unpack_from('>I',sealed,8)[0];assert n==private.key_size//8
    key=private.decrypt(sealed[12:12+n],padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
    data=AESGCM(key).decrypt(sealed[12+n:24+n],sealed[24+n:],b'MalGuard site-gated desktop 1.3.1:'+meta['source_commit'].encode())
    assert len(data)==meta['size'] and hashlib.sha256(data).hexdigest()==meta['sha256'] and data[:2]==b'MZ'
    VAULT.mkdir(mode=0o700,exist_ok=True)
    installer=VAULT/meta['filename'];installer.write_bytes(data);installer.chmod(0o600)
    code_file=VAULT/'download-code'
    if not code_file.exists():
        token=base64.b32encode(os.urandom(20)).decode()
        code_file.write_text('MG-'+'-'.join(token[i:i+8] for i in range(0,32,8))+'\n');code_file.chmod(0o600)
    code=re.sub(r'[-\s]','',code_file.read_text().strip().upper());assert re.fullmatch('MG[A-Z2-7]{32}',code)
    salt_file=VAULT/'download-salt'
    if not salt_file.exists():salt_file.write_bytes(os.urandom(32));salt_file.chmod(0o600)
    salt=salt_file.read_bytes();assert len(salt)==32
    key=HKDF(algorithm=hashes.SHA256(),length=32,salt=salt,info=('MalGuard site download v1:'+meta['build']).encode()).derive(code.encode())
    nonce=os.urandom(12)
    ciphertext=b'MGDL1\0'+nonce+AESGCM(key).encrypt(nonce,data,('MGDL1:'+meta['build']).encode())
    service=SITE/'private-download-service';chunks=service/'sealed-installer';chunks.mkdir(exist_ok=True)
    for path in chunks.glob('*.sealed'):path.unlink()
    parts=[]
    for i,start in enumerate(range(0,len(ciphertext),4*1024*1024)):
        piece=ciphertext[start:start+4*1024*1024];name=f'{i:03d}.sealed';(chunks/name).write_bytes(piece)
        parts.append({'name':name,'size':len(piece)})
    server={k:meta[k] for k in ('filename','size','sha256','build')}
    server.update(sealedSha256=hashlib.sha256(ciphertext).hexdigest(),passwordSalt=salt.hex(),parts=parts)
    (service/'installer-release.mjs').write_text('export const metadata = Object.freeze('+json.dumps(server,indent=2)+');\n')
    published={'schemaVersion':'1.0.0','product':'MalGuard clean-room static scanner','platform':'windows-x64','version':meta['app_version'],'engineVersion':meta['engine_version'],'build':meta['build'],'sourceCommit':meta['source_commit'],'filename':meta['filename'],'size':meta['size'],'sha256':meta['sha256'],'installerFormat':'IExpress-PowerShell','authenticodeSigned':False,'partBytes':3*1024*1024,'partCount':(meta['size']+3*1024*1024-1)//(3*1024*1024),'serviceUrl':'https://malguard-private-download.vercel.app/api/installer','status':'password-download-ready','passwordRequired':True,'deviceLicenseRequired':False,'installerPasswordRequired':False,
      'changes':{
       'en':['Content-based file type, size, bounded preview and specific unsupported/malformed explanations.','Actual scan stages, circular light animation and a 0–100 needle gauge; unsupported input has unknown risk.','Reversible evidence card with PNG and full JSON download.','Stronger bounded static analysis, signed intelligence and English/Persian interface.','Visible installation stages and bounded engine waits; website password only, without archive or device restrictions.'],
       'fa':['تشخیص نوع واقعی فایل، اندازه، پیش‌نمایش محدود و توضیح دقیق فایل پشتیبانی‌نشده یا معیوب.','مرحله‌های واقعی اسکن، حلقهٔ نور و عقربهٔ ریسک صفر تا صد؛ ریسک فایل پشتیبانی‌نشده نامشخص است.','کارت شواهد با قابلیت برگرداندن، دانلود PNG و گزارش کامل JSON.','تحلیل ایستای محدود تقویت‌شده، اطلاعات تهدید امضاشده و رابط انگلیسی/فارسی.','مرحله‌های قابل مشاهدهٔ نصب و انتظار محدود موتور؛ رمز فقط پیش از دانلود در سایت، بدون محدودیت دستگاه یا رمز بسته.']},
      'onlineUpdates':{'configured':True,'windowsClientVerified':True,'verifiedRecords':online['record_count'],'verifiedEpoch':online['epoch']},
      'verification':{'installedSyntheticFixtures':fixtures['fixtures'],'linux':{'passed':1006,'skipped':1},'windows':{'passed':passed,'skipped':skipped},'nativeInstallChecks':16,'setupDeadlineChecks':5,'desktopBrowserChecks':57,'passwordServiceUnitChecks':19,'nativeWindowsVerified':True,'windows10_11LaptopVerified':False,'corpusMetricsAvailable':False,'aiAdapterConfigured':False,'windowsRunId':meta['run_id']}}
    (SITE/'release/malguard-current-release.json').write_text(json.dumps(published,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'build':meta['build'],'sha256':meta['sha256'],'size':meta['size'],'windows_passed':passed,'published_ciphertext_only':True}))

if __name__=='__main__':main()
