"""Local owner-only delivery; never put generated licenses/passwords in Git."""

import argparse
import base64
import hashlib
import json
import lzma
import re
import secrets
import struct
import tempfile
from pathlib import Path

import py7zr
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

VAULT = Path("/workspace/.private-malguard-1.3")
ARTIFACTS = Path("/workspace/malguard-core/build/private-delivery")
ROOT = Path(__file__).resolve().parent
DOMAIN = b"MalGuard device license v1\x00"


def load_metadata():
    manifest = json.loads((ARTIFACTS / "private-release.json").read_text(encoding="utf-8-sig"))
    status = json.loads((ARTIFACTS / "build-status.json").read_text(encoding="utf-8-sig"))
    assert manifest["status"] == "private-windows-build-verified"
    assert manifest["app_version"] == "1.3.0" and manifest["engine_version"] == "1.2.0"
    assert re.fullmatch(r"[a-f0-9]{40}", manifest["source_commit"])
    assert status["result"] == "success" and status["source_commit"] == manifest["source_commit"]
    assert status["run_id"] == manifest["run_id"]
    assert manifest["requires_device_license"] is True
    for name in ("gui-install-qa.json", "device-license-qa.json", "production-license-qa.json"):
        qa = json.loads((ARTIFACTS / name).read_text(encoding="utf-8-sig"))
        assert qa["failed"] == 0 and qa["passed"] > 0
    return manifest


def decrypt_installer(manifest, password):
    sealed = (ARTIFACTS / "MalGuard-Online-Setup-x64.exe.sealed").read_bytes()
    assert hashlib.sha256(sealed).hexdigest() == manifest["sealed_sha256"]
    assert sealed[:8] == b"MGBUILD2" and len(sealed) <= 65 * 1024 * 1024
    key = serialization.load_pem_private_key((VAULT / "delivery.pem").read_bytes(), password)
    size = struct.unpack_from(">I", sealed, 8)[0]
    assert size == key.key_size // 8
    symmetric = key.decrypt(sealed[12:12 + size], padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None
    ))
    nonce = sealed[12 + size:24 + size]
    aad = b"MalGuard private desktop 1.3.0:" + manifest["source_commit"].encode("ascii")
    data = AESGCM(symmetric).decrypt(nonce, sealed[24 + size:], aad)
    assert len(data) == manifest["size"] and hashlib.sha256(data).hexdigest() == manifest["sha256"]
    assert data[:2] == b"MZ"
    path = VAULT / "MalGuard-Online-Setup-x64.exe"
    path.write_bytes(data)
    path.chmod(0o600)
    return path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--decrypt-only", action="store_true")
    parser.add_argument("--test-packaging", action="store_true")
    parser.add_argument("--fingerprint-file", type=Path)
    args = parser.parse_args()
    manifest = load_metadata()
    password = (VAULT / "vault-password").read_bytes()
    installer = decrypt_installer(manifest, password)
    if args.decrypt_only:
        print(json.dumps({"build": manifest["build"], "installer_sha256": manifest["sha256"],
                          "size": manifest["size"], "decrypted_and_verified": True}))
        return
    assert args.test_packaging or args.fingerprint_file is not None, "The owner's Windows fingerprint is required"
    fingerprint = "f" * 64 if args.test_packaging else args.fingerprint_file.read_text().strip().lower()
    assert re.fullmatch(r"[a-f0-9]{64}", fingerprint)
    activation = json.loads((ARTIFACTS / "activation-qa.json").read_text(encoding="utf-8-sig"))
    assert activation["failed"] == 0 and activation["passed"] >= 5
    signer = serialization.load_pem_private_key((VAULT / "license.pem").read_bytes(), password)
    assert signer.public_key().public_bytes_raw().hex() == manifest["license_public_key"]
    license = {"schema": 1, "product": "MalGuard", "app_version": "1.3.0",
               "fingerprint": fingerprint}
    message = DOMAIN + json.dumps(license, sort_keys=True, separators=(",", ":")).encode("utf-8")
    license["signature"] = base64.b64encode(signer.sign(message)).decode("ascii")
    from malguard_cli.device_license import verify_license
    verify_license(json.dumps(license).encode(), manifest["license_public_key"], fingerprint)
    bundle = VAULT / ("delivery-fixture" if args.test_packaging else "delivery")
    bundle.mkdir(mode=0o700, exist_ok=True)
    (bundle / "device-license.json").write_text(json.dumps(license, indent=2), encoding="utf-8")
    (bundle / "private-release.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    (bundle / "Activate-MalGuard.ps1").write_bytes((ROOT / "Activate-MalGuard.ps1").read_bytes())
    (bundle / "Install-MalGuard.cmd").write_bytes((ROOT / "Install-MalGuard.cmd").read_text().replace("\n", "\r\n").encode("ascii"))
    (bundle / "README-FA.txt").write_text(
        "MalGuard 1.3.0 — نسخهٔ خصوصی همین دستگاه\n\n"
        "بسته را با 7-Zip و رمز تحویل‌شده فقط در چت باز کنید.\n"
        "همهٔ فایل‌ها را در یک پوشه نگه دارید و Install-MalGuard.cmd را اجرا کنید.\n"
        "درخواست مدیر سیستم برای ثبت مجوز و نصب است. رمز داخل برنامه ذخیره نمی‌شود.\n"
        "مجوز امضاشده هنگام نصب و هر بار اجرا با همین ویندوز تطبیق می‌یابد.\n"
        "پس از نصب مجدد ویندوز ممکن است صدور مجوز تازه لازم شود.\n"
        "این نصب‌کننده امضای Authenticode ندارد؛ حفاظت ویندوز را خاموش نکنید.\n"
        "کپی ساده به دستگاه دیگر اجرا نمی‌شود؛ مدیر سیستم می‌تواند نرم‌افزار یا شناسهٔ ویندوز را دستکاری کند.\n"
        "نسخه‌های عمومی قبلی محدود نشده‌اند. آزمون نصب روی دستگاه شما هنوز انجام نشده است.\n\n"
        + "Build: " + manifest["build"] + "\nSHA256: " + manifest["sha256"] + "\n",
        encoding="utf-8-sig"
    )
    token_file = VAULT / ("test-password" if args.test_packaging else "download-password")
    if not token_file.exists():
        token_file.write_text(secrets.token_urlsafe(24), encoding="ascii")
        token_file.chmod(0o600)
    token = token_file.read_text(encoding="ascii")
    output = VAULT / "packaging-fixture.7z" if args.test_packaging else Path("/workspace/MalGuard-1.3.0-Private-Win64.7z")
    with py7zr.SevenZipFile(output, "w", password=token, header_encryption=True) as archive:
        archive.write(installer, arcname=installer.name)
        for name in ("device-license.json", "private-release.json", "Activate-MalGuard.ps1",
                     "Install-MalGuard.cmd", "README-FA.txt"):
            archive.write(bundle / name, arcname=name)
    output.chmod(0o600)
    with tempfile.TemporaryDirectory(prefix="delivery-verify-", dir=VAULT) as temporary:
        destination = Path(temporary)
        with py7zr.SevenZipFile(output, "r", password=token) as archive:
            assert len(archive.getnames()) == 6
            archive.extractall(destination)
        assert hashlib.sha256((destination / installer.name).read_bytes()).hexdigest() == manifest["sha256"]
        verify_license((destination / "device-license.json").read_bytes(),
                       manifest["license_public_key"], fingerprint)
        denied_count = 0
        for denied in (None, secrets.token_urlsafe(24)):
            try:
                with py7zr.SevenZipFile(output, "r", password=denied) as archive:
                    archive.getnames()
            except (py7zr.exceptions.PasswordRequired, py7zr.exceptions.Bad7zFile, lzma.LZMAError):
                denied_count += 1
            else:
                raise AssertionError("Missing or incorrect password revealed encrypted headers")
        assert denied_count == 2
    print(json.dumps({"file": str(output), "sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
                      "build": manifest["build"], "password_kept_private": True,
                      "test_fixture_only": args.test_packaging, "archive_round_trip_verified": True}))


if __name__ == "__main__":
    main()
