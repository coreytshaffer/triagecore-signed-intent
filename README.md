# TriageCore Signed Intent

An isolated YubiKey 5.8 previewSign experiment for portable authorization evidence.

It freezes a human-readable release intent into one canonical authorization
request, hashes the exact canonical bytes, and asks a YubiKey to produce a
previewSign/ARKG P-256 signature. The resulting package can be verified
offline and rejects changes to the bound request, intent, scope, or release
reference.

## What it demonstrates

```text
human-readable release intent
        -> canonical authorization request
        -> SHA-256 exact request digest
        -> YubiKey touch / previewSign
        -> ARKG P-256 signature
        -> portable evidence and offline verification
```

The release intent binds publication to the exact reviewed Git commit, not a
mutable branch name.

## Quickstart

Use Python 3.12 and a non-production YubiKey 5.8 test identity.

```powershell
git clone https://github.com/coreytshaffer/triagecore-signed-intent.git
cd triagecore-signed-intent
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pytest -q
```

Freeze a release request after committing the exact release candidate:

```powershell
.\.venv\Scripts\python.exe prepare_release_request.py `
  --commit <exact-release-candidate-sha> `
  --expires-at 2026-08-06T15:00:00+00:00
```

On Windows, run the signing ceremony from an Administrator PowerShell window;
the experimental native WebAuthn path may not otherwise return previewSign
extension data.

```powershell
.\.venv\Scripts\python.exe -u sign_authorization.py
.\.venv\Scripts\python.exe verify_authorization.py
.\.venv\Scripts\python.exe verify_authorization.py --tamper decision_id
```

The signing script displays the frozen human-readable intent before requesting
the two physical interactions used by the ARKG setup and signing ceremony.

## Boundaries and security claims

- This uses beta/preview YubiKey 5.8 interfaces and is not for production
  credentials.
- The evidence contains public verification material, not a private key or PIN.
- A hardware interaction shows credential use; it does not establish human
  comprehension or informed consent.
- This project does not assert device attestation or a YubiKey model identity.
- This experiment does not integrate with `tc run` or downstream execution.
- TriageCore's separately established capability component demonstrates atomic
  one-use claiming and replay rejection. This project does not connect that
  component to previewSign or claim end-to-end execution enforcement.

## Attribution

The FIDO/ARKG ceremony in `sign_authorization.py` is adapted from the
[YubicoLabs build-with-us quickstart](https://github.com/YubicoLabs/build-with-us).
That file retains its Yubico license notice. The remaining project files are
licensed under MIT; see [LICENSE](LICENSE).
