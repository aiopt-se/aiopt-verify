"""Independent test for aiopt-verify, with no dependency on the AIOpt platform.

It builds packs with make_sample_pack (cryptography-only) and asserts the
verifier passes a clean pack and FAILS every tamper: modification, middle
deletion, last-record truncation, wrong key, and, for two-party packs, a
stripped or wrong actor signature. With the expected keys pinned it also fails
a pack re-signed with another key, a two-party pack cut down to one signature,
and a two-party pack shortened and resealed with AIOpt's key alone.

Run:  pip install cryptography pytest && pytest test_aiopt_verify.py
"""
import base64
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import aiopt_verify as v
from make_sample_pack import _fingerprint, build_pack, write_manifest


def _failed(checks):
    return [name for name, ok, _ in checks if not ok]


def test_clean_single_party_verifies(tmp_path):
    build_pack(tmp_path, two_party=False)
    ok, checks = v.verify_pack(str(tmp_path))
    assert ok, _failed(checks)


def test_clean_two_party_verifies(tmp_path):
    build_pack(tmp_path, two_party=True)
    ok, checks = v.verify_pack(str(tmp_path))
    assert ok, _failed(checks)
    assert "actor_signatures" in [n for n, _, _ in checks]


def test_modified_record_fails(tmp_path):
    build_pack(tmp_path, two_party=False)
    lines = (tmp_path / "ledger.jsonl").read_text().splitlines()
    rec = json.loads(lines[1]); rec["payload"]["seq_note"] = 999
    lines[1] = json.dumps(rec, sort_keys=True)
    (tmp_path / "ledger.jsonl").write_text("\n".join(lines) + "\n")
    ok, checks = v.verify_pack(str(tmp_path))
    assert not ok
    assert "record_signatures" in _failed(checks) and "ledger_digest" in _failed(checks)


def test_deleted_middle_record_fails(tmp_path):
    build_pack(tmp_path, two_party=False)
    lines = (tmp_path / "ledger.jsonl").read_text().splitlines()
    del lines[1]
    (tmp_path / "ledger.jsonl").write_text("\n".join(lines) + "\n")
    ok, checks = v.verify_pack(str(tmp_path))
    assert not ok
    assert "chain_linkage" in _failed(checks) and "manifest_count" in _failed(checks)


def test_truncated_last_record_fails(tmp_path):
    """The headline property: dropping the newest record is detected."""
    build_pack(tmp_path, two_party=False)
    lines = (tmp_path / "ledger.jsonl").read_text().splitlines()[:-1]
    (tmp_path / "ledger.jsonl").write_text("\n".join(lines) + "\n")
    ok, checks = v.verify_pack(str(tmp_path))
    assert not ok
    for name in ("manifest_count", "manifest_head", "ledger_digest"):
        assert name in _failed(checks)


def test_wrong_pubkey_fails(tmp_path):
    build_pack(tmp_path, two_party=False)
    other = Ed25519PrivateKey.generate()
    (tmp_path / "pubkey.pem").write_bytes(other.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo))
    ok, checks = v.verify_pack(str(tmp_path))
    assert not ok
    assert "pubkey_fingerprint" in _failed(checks)


def test_two_party_stripped_actor_signature_fails(tmp_path):
    build_pack(tmp_path, two_party=True)
    lines = (tmp_path / "ledger.jsonl").read_text().splitlines()
    rec = json.loads(lines[1]); rec.pop("actor_signature")
    lines[1] = json.dumps(rec, sort_keys=True)
    (tmp_path / "ledger.jsonl").write_text("\n".join(lines) + "\n")
    ok, checks = v.verify_pack(str(tmp_path))
    assert not ok
    assert "actor_signatures" in _failed(checks)


def test_forged_manifest_without_key_fails(tmp_path):
    build_pack(tmp_path, two_party=False)
    (tmp_path / "ledger.jsonl").write_text("")
    manifest = json.loads((tmp_path / "manifest.json").read_text())
    manifest["record_count"] = 0
    manifest["manifest_signature"] = base64.b64encode(b"\x00" * 64).decode()
    (tmp_path / "manifest.json").write_text(json.dumps(manifest))
    ok, checks = v.verify_pack(str(tmp_path))
    assert not ok
    assert "manifest_signature" in _failed(checks)


# ---------------------------------------------------------------- pinned keys
def _warned(report, text):
    return any(text in w for w in report["warnings"])


def _resign(pack, key, actor=None):
    """What the holder of `key` can do: edit, re-sign every record, reseal."""
    lines = (pack / "ledger.jsonl").read_text().splitlines()
    out, prev = [], "0" * 64
    for line in lines:
        rec = json.loads(line)
        rec["prev_hash"] = prev
        core = {k: rec[k] for k in ("seq", "timestamp", "kind", "payload", "prev_hash")}
        body = v.canon(core)
        rec["record_hash"] = v.sha256_hex(body)
        rec["signature"] = base64.b64encode(key.sign(body)).decode()
        rec.pop("actor_signature", None)
        if actor is not None:
            rec["actor_signature"] = base64.b64encode(actor.sign(body)).decode()
        prev = rec["record_hash"]
        out.append(json.dumps(rec, sort_keys=True))
    (pack / "ledger.jsonl").write_text("\n".join(out) + "\n")


def test_pinned_keys_pass_a_clean_pack(tmp_path):
    op, actor = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    build_pack(tmp_path, two_party=True, op=op, actor=actor)
    r = v.inspect_pack(tmp_path, [_fingerprint(op.public_key())],
                       [_fingerprint(actor.public_key())])
    assert r["ok"], _failed(r["checks"])
    assert r["keys"]["cosigner_key"] == _fingerprint(actor.public_key())
    assert not _warned(r, "not pinned") and not r["warnings"]


def test_resigned_pack_passes_unpinned_but_fails_pinned(tmp_path):
    """Issue #12: a pack re-signed with any other key fails once the key is pinned."""
    op, attacker = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    build_pack(tmp_path, op=op)
    rec = json.loads((tmp_path / "ledger.jsonl").read_text().splitlines()[1])
    assert rec["payload"]["verdict"] == "COUNTERSIGNED_REFUSAL"
    text = (tmp_path / "ledger.jsonl").read_text().replace(
        "COUNTERSIGNED_REFUSAL", "COUNTERSIGNED_PASS")
    (tmp_path / "ledger.jsonl").write_text(text)
    _resign(tmp_path, attacker)
    write_manifest(tmp_path, attacker)

    unpinned = v.inspect_pack(tmp_path)
    assert unpinned["ok"] and _warned(unpinned, "keys not pinned")
    pinned = v.inspect_pack(tmp_path, [_fingerprint(op.public_key())])
    assert not pinned["ok"]
    assert _failed(pinned["checks"]) == ["pinned_key"]


def test_downgrade_to_one_signature_fails_when_a_cosigner_is_expected(tmp_path):
    """Issue #13: AIOpt's key alone rebuilds a two-party pack as single-party."""
    op, actor = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    build_pack(tmp_path, two_party=True, op=op, actor=actor)
    _resign(tmp_path, op)  # drops every co-signature
    for name in ("pubkey_actor.pem", "cosign_statement.json"):
        (tmp_path / name).unlink()
    write_manifest(tmp_path, op)

    assert v.inspect_pack(tmp_path, [_fingerprint(op.public_key())])["ok"]
    for pins in ({"expect_cosigners": [_fingerprint(actor.public_key())]},
                 {"require_two_party": True}):
        r = v.inspect_pack(tmp_path, [_fingerprint(op.public_key())], **pins)
        assert not r["ok"] and "two_party_required" in _failed(r["checks"])


def test_two_party_pack_shortened_by_aiopt_key_alone_fails(tmp_path):
    """Every remaining record still carries both signatures; the co-signer's
    statement is what shows records were dropped from the end."""
    op, actor = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    build_pack(tmp_path, two_party=True, op=op, actor=actor, n=4)
    lines = (tmp_path / "ledger.jsonl").read_text().splitlines()[:-1]
    (tmp_path / "ledger.jsonl").write_text("\n".join(lines) + "\n")
    write_manifest(tmp_path, op, actor.public_key())

    ok, checks = v.verify_pack(str(tmp_path))
    assert not ok
    assert _failed(checks) == ["cosigner_statement"]


def test_shortened_pack_with_statement_removed_fails_when_cosigner_expected(tmp_path):
    op, actor = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    build_pack(tmp_path, two_party=True, op=op, actor=actor, n=4)
    lines = (tmp_path / "ledger.jsonl").read_text().splitlines()[:-1]
    (tmp_path / "ledger.jsonl").write_text("\n".join(lines) + "\n")
    (tmp_path / "cosign_statement.json").unlink()
    write_manifest(tmp_path, op, actor.public_key())

    loose = v.inspect_pack(tmp_path)
    assert loose["ok"] and _warned(loose, "no co-signer statement")
    strict = v.inspect_pack(tmp_path, [_fingerprint(op.public_key())],
                            [_fingerprint(actor.public_key())])
    assert _failed(strict["checks"]) == ["cosigner_statement"]


def test_cosigner_swapped_for_another_key_fails_when_pinned(tmp_path):
    op, operator, stand_in = (Ed25519PrivateKey.generate() for _ in range(3))
    build_pack(tmp_path, two_party=True, op=op, actor=stand_in)
    r = v.inspect_pack(tmp_path, [_fingerprint(op.public_key())],
                       [_fingerprint(operator.public_key())])
    assert _failed(r["checks"]) == ["pinned_cosigner"]


def test_forged_cosigner_statement_fails(tmp_path):
    build_pack(tmp_path, two_party=True)
    stmt = json.loads((tmp_path / "cosign_statement.json").read_text())
    stmt["record_count"] = 2
    (tmp_path / "cosign_statement.json").write_text(json.dumps(stmt))
    ok, checks = v.verify_pack(str(tmp_path))
    assert _failed(checks) == ["cosigner_statement"]


def test_older_two_party_pack_without_statement_still_verifies_with_a_warning(tmp_path):
    build_pack(tmp_path, two_party=True, statement=False)
    r = v.inspect_pack(tmp_path)
    assert r["ok"] and _warned(r, "no co-signer statement")
    assert not v.inspect_pack(tmp_path, require_two_party=True)["ok"]


def _ots_for(data: bytes) -> bytes:
    return v.OTS_MAGIC + bytes([0x01, v.OTS_SHA256]) + hashlib.sha256(data).digest() + b"\xf0"


def test_timestamp_proof_must_belong_to_this_manifest(tmp_path):
    manifest = build_pack(tmp_path)
    hash_file = tmp_path / "manifest.hash"
    hash_file.write_text(manifest["manifest_hash"] + "\n")
    (tmp_path / "manifest.hash.ots").write_bytes(_ots_for(hash_file.read_bytes()))
    assert v.verify_pack(str(tmp_path))[0]

    (tmp_path / "manifest.hash.ots").write_bytes(_ots_for(b"another manifest\n"))
    assert _failed(v.verify_pack(str(tmp_path))[1]) == ["anchor_proof_matches"]
    hash_file.write_text("0" * 64 + "\n")
    assert _failed(v.verify_pack(str(tmp_path))[1]) == ["anchor_hash_file"]


def _cli(*args):
    return subprocess.run([sys.executable, str(Path(v.__file__)), *map(str, args)],
                          capture_output=True, text=True, timeout=60)


def test_cli_pins_file_json_and_bad_fingerprint(tmp_path):
    op, actor = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    pack = tmp_path / "pack"
    build_pack(pack, two_party=True, op=op, actor=actor)
    pins = tmp_path / "pins.json"
    pins.write_text(json.dumps({"expect_key": [_fingerprint(op.public_key())],
                                "expect_cosigner": [_fingerprint(actor.public_key())]}))
    res = _cli(pack, "--pins", pins, "--json")
    assert res.returncode == 0, res.stdout + res.stderr
    out = json.loads(res.stdout)
    assert out["keys"]["aiopt_key"] == _fingerprint(op.public_key())
    assert out["warnings"] == [] and out["verifier"].startswith("aiopt-verify 1.1")

    wrong = _cli(pack, "--expect-cosigner", _fingerprint(op.public_key()))
    assert wrong.returncode == 1 and "pinned_cosigner" in wrong.stdout
    assert _cli(pack, "--expect-key", "abc123").returncode == 2
