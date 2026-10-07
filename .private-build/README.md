# Private desktop delivery

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
