"""Independent test for aiopt-cosign: no dependency on the AIOpt platform.

It builds an unsealed ledger with `cryptography` alone, signed by a stand-in
for AIOpt's key, and checks that the tool co-signs only intact records, never
with the same key, never a sealed pack, and that its receipt catches a pack
that was cut short after co-signing.

Run:  pip install cryptography pytest && pytest test_aiopt_cosign.py
"""
import base64
import hashlib
import json
import os
import stat

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import aiopt_cosign as c


def _canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def _unsealed(pack, n=3, key=None):
    """A ledger signed by `key` (AIOpt's role) plus pubkey.pem, no manifest."""
    key = key or Ed25519PrivateKey.generate()
    prev, lines = "0" * 64, []
    for i in range(n):
        core = {
            "seq": i,
            "timestamp": f"2026-09-26T00:0{i}:00+00:00",
            "kind": "countersign_verdict",
            "payload": {"verdict": "COUNTERSIGNED_REFUSAL", "n": i},
            "prev_hash": prev,
        }
        rh = hashlib.sha256(_canon(core)).hexdigest()
        sig = base64.b64encode(key.sign(_canon(core))).decode()
        lines.append(json.dumps({**core, "record_hash": rh, "signature": sig}, sort_keys=True))
        prev = rh
    pack.mkdir(parents=True, exist_ok=True)
    (pack / "ledger.jsonl").write_text("\n".join(lines) + "\n")
    (pack / "pubkey.pem").write_bytes(key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo))
    return key


def _records(pack):
    return [json.loads(x) for x in (pack / "ledger.jsonl").read_text().splitlines() if x]


def _seal_like_aiopt(pack):
    """The manifest fields `check` compares (the real seal lives in AIOpt)."""
    recs, raw = _records(pack), (pack / "ledger.jsonl").read_bytes()
    (pack / "manifest.json").write_text(json.dumps({
        "record_count": len(recs),
        "head_hash": recs[-1]["record_hash"],
        "ledger_sha256": hashlib.sha256(raw).hexdigest(),
    }))


@pytest.fixture()
def cosign_key(tmp_path):
    path = tmp_path / "mine" / "cosign.pem"
    c.keygen(path)
    return path


def test_keygen_is_private_and_never_overwrites(cosign_key):
    assert stat.S_IMODE(os.stat(cosign_key).st_mode) == 0o600
    with pytest.raises(c.Refused):
        c.keygen(cosign_key)


def test_sign_adds_a_verifiable_cosignature_to_every_record(tmp_path, cosign_key):
    pack = tmp_path / "pack"
    _unsealed(pack)
    receipt = c.sign(pack, cosign_key, tmp_path / "receipt.json", assume_yes=True,
                     out=lambda *_: None)

    pub = serialization.load_pem_public_key((pack / "pubkey_actor.pem").read_bytes())
    recs = _records(pack)
    for rec in recs:
        pub.verify(base64.b64decode(rec["actor_signature"]), c.core_bytes(rec))
    assert receipt["record_count"] == 3
    assert receipt["head_hash"] == recs[-1]["record_hash"]
    assert not (pack / "manifest.json").exists()


def test_refuses_a_changed_record(tmp_path, cosign_key):
    pack = tmp_path / "pack"
    _unsealed(pack)
    recs = _records(pack)
    recs[1]["payload"]["verdict"] = "COUNTERSIGNED_PASS"
    (pack / "ledger.jsonl").write_text("".join(json.dumps(r) + "\n" for r in recs))
    with pytest.raises(c.Refused, match="record 1"):
        c.sign(pack, cosign_key, assume_yes=True, out=lambda *_: None)
    assert not (pack / "pubkey_actor.pem").exists()


def test_refuses_a_removed_middle_record(tmp_path, cosign_key):
    pack = tmp_path / "pack"
    _unsealed(pack)
    recs = _records(pack)
    del recs[1]
    (pack / "ledger.jsonl").write_text("".join(json.dumps(r) + "\n" for r in recs))
    with pytest.raises(c.Refused, match="chain"):
        c.sign(pack, cosign_key, assume_yes=True, out=lambda *_: None)


def test_refuses_the_same_key_as_the_signer(tmp_path):
    pack = tmp_path / "pack"
    system = Ed25519PrivateKey.generate()
    _unsealed(pack, key=system)
    same = tmp_path / "same.pem"
    same.write_bytes(system.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()))
    with pytest.raises(c.Refused, match="same key"):
        c.sign(pack, same, assume_yes=True, out=lambda *_: None)


def test_refuses_a_sealed_pack(tmp_path, cosign_key):
    pack = tmp_path / "pack"
    _unsealed(pack)
    (pack / "manifest.json").write_text("{}")
    with pytest.raises(c.Refused, match="sealed"):
        c.sign(pack, cosign_key, assume_yes=True, out=lambda *_: None)


def test_without_confirmation_nothing_is_signed(tmp_path, cosign_key, monkeypatch):
    pack = tmp_path / "pack"
    _unsealed(pack)
    before = (pack / "ledger.jsonl").read_bytes()
    monkeypatch.setattr("builtins.input", lambda *_: "n")
    with pytest.raises(c.Refused, match="not confirmed"):
        c.sign(pack, cosign_key, out=lambda *_: None)
    assert (pack / "ledger.jsonl").read_bytes() == before


def test_receipt_catches_a_pack_cut_short_after_cosigning(tmp_path, cosign_key):
    pack = tmp_path / "pack"
    _unsealed(pack)
    c.sign(pack, cosign_key, tmp_path / "receipt.json", assume_yes=True,
           out=lambda *_: None)
    _seal_like_aiopt(pack)
    assert c.check(pack, tmp_path / "receipt.json", out=lambda *_: None)

    # The signer alone drops the last record and seals again: every remaining
    # record still carries both signatures, but the receipt shows the cut.
    lines = (pack / "ledger.jsonl").read_text().splitlines(keepends=True)
    (pack / "ledger.jsonl").write_text("".join(lines[:-1]))
    _seal_like_aiopt(pack)
    assert not c.check(pack, tmp_path / "receipt.json", out=lambda *_: None)


def test_cli_exit_codes(tmp_path, cosign_key):
    pack = tmp_path / "pack"
    _unsealed(pack)
    receipt = str(tmp_path / "r.json")
    assert c.main(["sign", str(pack), "--key", str(cosign_key), "--yes",
                   "--receipt", receipt]) == 0
    # Signing again with the same key is fine.
    assert c.main(["sign", str(pack), "--key", str(cosign_key), "--yes",
                   "--receipt", receipt]) == 0
    assert c.main(["sign", str(tmp_path / "missing"), "--key", str(cosign_key)]) == 2
    (pack / "manifest.json").write_text("{}")
    assert c.main(["sign", str(pack), "--key", str(cosign_key), "--yes"]) == 1


def test_tool_is_standalone_and_offline():
    import ast

    src = open(c.__file__).read()
    imported = set()
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Import):
            imported |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            imported.add((node.module or "").split(".")[0])
    # stdlib plus cryptography: no AIOpt code, nothing that talks to a network
    assert imported <= {"argparse", "base64", "hashlib", "json", "os", "sys",
                        "collections", "pathlib", "getpass", "cryptography"}, imported
