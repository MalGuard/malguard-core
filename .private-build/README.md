# Current delivery: website password only

The current 1.3.1 / engine 1.2.1 source has no device license gate. The
site-gated-windows workflow builds it without a private-policy override, verifies
16 native installation checks and five stage/deadline checks, and publishes only
RSA-OAEP/AES-GCM installer ciphertext and bounded evidence to
`codex/malguard-site-gated-1-3-1-artifacts`. The RSA public recipient remains useful
for confidential delivery; it does not impose any installation license.

`private-delivery/package_site_gated_release.py` verifies the exact build and
acceptance evidence, unwraps the installer in the local private vault, and reseals
it for the website using the new random 160-bit download code. The installer has
no archive or installation password and may be copied after download. Only the
website server asks for the download code. No code, derived key, device identifier
or plaintext installer belongs in Git. The production website lives in
MalGuard/malguard.github.io; its private-download-service directory deploys through
the owner's existing Vercel Git connection.

The private-windows/private-activation workflows, licensing public key and earlier
activation scripts describe the historical device-bound 1.3.0 release. They are
not part of the current release. The previous delivery design is retained below
for historical reproducibility.

# Historical private desktop delivery

This branch builds MalGuard desktop 1.3.0 / engine 1.2.0 with the owner's
Ed25519 public licensing key compiled into the frozen engine. The source
archive is the public variant; CI selects the immutable private policy before
freezing. No runtime environment flag disables licensing.

CI acceptance uses a separate ephemeral signer for its Windows runner. Tests
cover same-device acceptance, wrong-device rejection, signature mutation,
missing-license rejection, GUI installation, update scheduling and uninstall.
The production engine is rebuilt with the owner key and must reject the CI
license during execution and installation. Installation on the owner's actual
Windows device is still required after delivery.

Only RSA-OAEP/AES-GCM ciphertext and bounded test evidence are committed to
codex/malguard-private-1-3-artifacts. Plaintext installers, owner device licenses,
passwords and private keys never belong in Git or logs. AES-GCM authenticates
the full source commit. The owner license is delivered privately with a local
activation script, which writes the license to protected Windows ProgramData
and starts setup. The engine verifies its Ed25519 signature and compares the
local 64-bit Windows MachineGuid hash without uploading any identifier.

Setup checks authorization before prerequisites, tasks, shortcuts or replacing
an existing installation. GUI startup and frozen engine entry points enforce
it again, including workers and updates. No sample is executed.

Reinstalling Windows can require a new license. This restricts ordinary copying
of this binary; an administrator can still patch software, spoof an operating
system identity or compile public source. Previous public releases remain
available. No Authenticode certificate has been added.
