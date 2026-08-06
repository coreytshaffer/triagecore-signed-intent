# Copyright (c) 2024 Yubico AB
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DAMAGES ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE.

"""Experimental YubiKey 5.8 previewSign adapter for one canonical request.

The FIDO/ARKG ceremony is adapted from YubicoLabs/build-with-us
quickstart/python/example_arkg.py and exampleutils.py. TriageCore production
authorization and execution paths are deliberately not imported or modified.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import sys
from getpass import getpass
from pathlib import Path

from fido2 import cbor
from fido2.client import DefaultClientDataCollector, Fido2Client, UserInteraction
from fido2.cose import ESP256_SPLIT_ARKG_PLACEHOLDER, CoseKey
from fido2.ctap2.extensions import PreviewSignExtension
from fido2.hid import CtapHidDevice
from fido2.server import Fido2Server
from fido2.utils import sha256, websafe_decode, websafe_encode

try:
    from fido2.pcsc import CtapPcscDevice
except ImportError:
    CtapPcscDevice = None

try:
    from .evidence import (
        SIGNING_CONTEXT,
        build_evidence,
        load_request,
        request_digest,
        validate_review_binding,
        verify_evidence,
    )
except ImportError:  # Direct script execution from this directory.
    from evidence import (  # type: ignore[no-redef]
        SIGNING_CONTEXT,
        build_evidence,
        load_request,
        request_digest,
        validate_review_binding,
        verify_evidence,
    )


class CliInteraction(UserInteraction):
    def __init__(self) -> None:
        self._pin: str | None = None

    def prompt_up(self) -> None:
        print("\nTouch the hackathon YubiKey now...\n", flush=True)

    def request_pin(self, permissions, rd_id):
        if not self._pin:
            self._pin = getpass("Enter test-key PIN: ")
        return self._pin

    def request_uv(self, permissions, rd_id):
        print("User verification required.", flush=True)
        return True


def enumerate_devices():
    yield from CtapHidDevice.list_devices()
    if CtapPcscDevice:
        yield from CtapPcscDevice.list_devices()


def get_client(origin: str) -> Fido2Client:
    collector = DefaultClientDataCollector(origin)
    for device in enumerate_devices():
        client = Fido2Client(
            device,
            client_data_collector=collector,
            user_interaction=CliInteraction(),
            extensions=[PreviewSignExtension()],
        )
        if PreviewSignExtension.NAME in (client.info.extensions or []):
            return client
    raise RuntimeError("no connected authenticator exposes previewSign")


def is_windows_admin() -> bool:
    if sys.platform != "win32":
        return True
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def parse_args() -> argparse.Namespace:
    directory = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--request",
        type=Path,
        default=directory / "authorization-request.json",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=directory / "authorization-evidence.json",
    )
    parser.add_argument(
        "--review",
        type=Path,
        default=directory / "release-review.json",
        help="frozen human-readable intent and scope generated with the request",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    request = load_request(args.request)
    try:
        review = json.loads(args.review.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"cannot read frozen release review: {exc}") from exc
    if not isinstance(review, dict):
        raise RuntimeError("frozen release review must be a JSON object")
    validate_review_binding(request, review)
    if request.user_verification_required:
        raise RuntimeError(
            "this touch-only preview experiment requires "
            "user_verification_required=false"
        )
    if not is_windows_admin():
        raise RuntimeError("Windows previewSign requires an Administrator terminal")

    message = request.canonical_bytes()
    digest = hashlib.sha256(message).digest()
    print("PROPOSED RELEASE AUTHORIZATION", flush=True)
    print(json.dumps(review["intent"], indent=2), flush=True)
    print(f"Canonical request digest: {request_digest(request)}", flush=True)
    print("This permits one bounded authorization request only.", flush=True)
    print("It does not authorize execution, other files, or network access.", flush=True)

    client = get_client(f"https://{request.rp_id}")
    server = Fido2Server(
        {"id": request.rp_id, "name": "TriageCore Signed Intent"},
        attestation="none",
    )
    user = {
        "id": sha256(request.approver_identity_id.encode("utf-8")),
        "name": request.approver_identity_id,
    }
    create_options, state = server.register_begin(
        user,
        resident_key_requirement="discouraged",
        user_verification="discouraged",
        authenticator_attachment="cross-platform",
    )
    created = client.make_credential(
        {
            **create_options["publicKey"],
            "extensions": {
                PreviewSignExtension.NAME: {
                    "generateKey": {"algorithms": [ESP256_SPLIT_ARKG_PLACEHOLDER]}
                }
            },
        }
    )
    auth_data = server.register_complete(state, created)
    credential = auth_data.credential_data
    sign_output = created.client_extension_results.previewSign
    if sign_output is None or sign_output.generated_key is None:
        raise RuntimeError("credential creation returned no previewSign generated key")

    generated = sign_output.generated_key
    master = CoseKey.parse(cbor.decode(websafe_decode(generated["publicKey"])))
    ikm = os.urandom(32)
    derived, sign_args = master.derive_public_key(ikm, SIGNING_CONTEXT)

    request_options, state = server.authenticate_begin(
        [credential], user_verification="discouraged"
    )
    assertion = client.get_assertion(
        {
            **request_options["publicKey"],
            "extensions": {
                PreviewSignExtension.NAME: {
                    "signByCredential": {
                        websafe_encode(credential.credential_id): {
                            "keyHandle": generated.key_handle,
                            "tbs": digest,
                            "additionalArgs": cbor.encode(sign_args),
                        }
                    }
                }
            },
        }
    ).get_response(0)
    server.authenticate_complete(state, [credential], assertion)
    assertion_output = assertion.client_extension_results[PreviewSignExtension.NAME]
    signature_value = assertion_output.get("signature")
    if not signature_value:
        raise RuntimeError("previewSign assertion returned no signature")
    signature = websafe_decode(signature_value)
    derived.verify(message, signature)

    evidence = build_evidence(
        request,
        master_public_key=master,
        derived_public_key=derived,
        ikm=ikm,
        signature=signature,
        review=review,
    )
    args.output.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    summary = verify_evidence(evidence)
    print("[OK] YubiKey 5.8 previewSign signature verified offline", flush=True)
    print(f"[OK] Request digest matched: {summary['request_digest']}", flush=True)
    print(f"Evidence written: {args.output}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
