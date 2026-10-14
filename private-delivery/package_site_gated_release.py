"""Publish the authenticated native Windows installer for unrestricted public download."""
import argparse
import hashlib
import json
import re
import struct
import xml.etree.ElementTree as ET
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SITE = Path('/workspace/malguard.github.io')
VAULT = Path('/workspace/.private-malguard-1.3')


def totals(path):
    root = ET.parse(path).getroot()
    suites = [root] if root.tag == 'testsuite' else list(root)
    assert suites and all(int(s.attrib.get('failures', 0)) == 0 and
                          int(s.attrib.get('errors', 0)) == 0 for s in suites)
    return {'passed': sum(int(s.attrib['tests'])-int(s.attrib.get('skipped', 0)) for s in suites),
            'skipped': sum(int(s.attrib.get('skipped', 0)) for s in suites)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--linux-tests', type=Path, required=True)
    args = parser.parse_args()
    assert re.fullmatch('[a-f0-9]{40}', args.source_commit)
    artifacts = args.artifacts
    meta = json.loads((artifacts/'site-gated-release.json').read_text(encoding='utf-8-sig'))
    status = json.loads((artifacts/'build-status.json').read_text(encoding='utf-8-sig'))
    source = json.loads(Path('/workspace/malguard-core/cleanroom-v1/source.json').read_text())
    assert meta['status'] == 'site-gated-windows-build-verified'
    assert meta['app_version'] == source['app_version'] == '1.3.2'
    assert meta['engine_version'] == source['engine_version'] == '1.2.2'
    assert meta['source_archive_sha256'] == source['sha256']
    assert meta['source_commit'] == args.source_commit == status['source_commit']
    assert status['result'] == 'success' and status['run_id'] == meta['run_id']
    assert meta['requires_device_license'] is False and meta['installer_password_required'] is False
    qa = json.loads((artifacts/'gui-install-qa.json').read_text(encoding='utf-8-sig'))
    deadlines = json.loads((artifacts/'setup-deadline-qa.json').read_text(encoding='utf-8-sig'))
    assert qa['failed'] == 0 and qa['passed'] == 18
    assert deadlines['failed'] == 0 and deadlines['passed'] == 5
    checks = {c['name']: c for c in qa['checks']}
    assert checks['installed-desktop-update-completion-and-counts']['passed']
    assert checks['update-progress-readonly-acl']['passed']
    online = checks['installed-signed-online-feed']
    fixtures = checks['installed-static-detection-and-bilingual-reports']
    assert online['passed'] and online['record_count'] > 0 and fixtures['fixtures'] >= 6
    windows, linux = totals(artifacts/'windows-tests.xml'), totals(args.linux_tests)
    assert windows['passed'] >= 1029 and linux['passed'] >= 1030
    sealed = (artifacts/'MalGuard-Setup-x64.exe.sealed').read_bytes()
    assert hashlib.sha256(sealed).hexdigest() == meta['sealed_sha256'] and sealed[:8] == b'MGBUILD2'
    private = serialization.load_pem_private_key((VAULT/'delivery.pem').read_bytes(),
                                                (VAULT/'vault-password').read_bytes())
    n = struct.unpack_from('>I', sealed, 8)[0]
    assert n == private.key_size//8
    key = private.decrypt(sealed[12:12+n], padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                          algorithm=hashes.SHA256(), label=None))
    aad = ('MalGuard site-gated desktop '+meta['app_version']+':'+meta['source_commit']).encode()
    data = AESGCM(key).decrypt(sealed[12+n:24+n], sealed[24+n:], aad)
    assert len(data) == meta['size'] and hashlib.sha256(data).hexdigest() == meta['sha256']
    assert data[:2] == b'MZ' and 0 < len(data) <= 40*1024*1024
    # The owner explicitly authorized public installer distribution. Keys and
    # previous download passwords remain in the private vault.
    (SITE/'release'/meta['filename']).write_bytes(data)
    (SITE/'release'/(meta['filename']+'.sha256')).write_text(meta['sha256']+'  '+meta['filename']+'\n')
    published = json.loads((SITE/'release/malguard-current-release.json').read_text())
    published.update(version=meta['app_version'], engineVersion=meta['engine_version'], build=meta['build'],
        sourceCommit=meta['source_commit'], filename=meta['filename'], size=meta['size'], sha256=meta['sha256'],
        partCount=(meta['size']+published['partBytes']-1)//published['partBytes'], status='public-download-ready',
        passwordRequired=False, deviceLicenseRequired=False, installerPasswordRequired=False,
        serviceUrl='/release/MalGuard-Setup-x64.exe')
    published['changes']['en'].insert(0, 'Public Windows download without a password or device restriction. One-click signed threat updates with real progress and exact new/already-present hash counts.')
    published['changes']['fa'].insert(0, 'دانلود عمومی ویندوز بدون رمز یا محدودیت دستگاه؛ دریافت اطلاعات جدید با یک دکمه، پیشرفت واقعی و شمارش دقیق هش‌های تازه و ازقبل‌موجود.')
    published['onlineUpdates'] = {'configured': True, 'windowsClientVerified': True,
        'verifiedRecords': online['record_count'], 'verifiedEpoch': online['epoch']}
    published['verification'].update(linux=linux, windows=windows, nativeInstallChecks=18,
        setupDeadlineChecks=5, desktopBrowserChecks=57, desktopUpdateBrowserChecks=35,
        passwordServiceUnitChecks=21, nativeWindowsVerified=True, windowsRunId=meta['run_id'])
    (SITE/'release/malguard-current-release.json').write_text(json.dumps(published, ensure_ascii=False, indent=2)+'\n')
    legacy = json.loads((SITE/'release/gta-guard-windows.json').read_text())
    legacy.update(version=meta['app_version'],engineVersion=meta['engine_version'],build=meta['build'],sourceCommit=meta['source_commit'])
    legacy['installer'].update(url='/release/MalGuard-Setup-x64.exe',sha256=meta['sha256'],sha256Url='/release/MalGuard-Setup-x64.exe.sha256')
    legacy['distribution'].update(status='public-download-ready',downloadEnabled=True,passwordRequired=False,deviceLicenseRequired=False)
    (SITE/'release/gta-guard-windows.json').write_text(json.dumps(legacy,ensure_ascii=False,indent=2)+'\n')
    history = json.loads((SITE/'release/malguard-release-history.json').read_text())
    for entry in history:
        if entry['build'] != meta['build']: entry['supersededBy'] = meta['build']
    if not any(entry['build'] == meta['build'] for entry in history):
        history.append({'build':meta['build'],'version':meta['app_version'],'sourceCommit':meta['source_commit']})
    (SITE/'release/malguard-release-history.json').write_text(json.dumps(history,indent=2)+'\n')
    print(json.dumps({'build':meta['build'],'sha256':meta['sha256'],'size':meta['size'],
        'windows_passed':windows['passed'],'public_download':True,'password_required':False}))


if __name__ == '__main__':
    main()
