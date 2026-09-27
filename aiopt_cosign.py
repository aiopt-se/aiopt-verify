#!/usr/bin/env python3
"""aiopt-cosign: the second party's own signature on an AIOpt evidence pack.

An AIOpt evidence pack can carry two signatures on every record. AIOpt's
software signs each record with its key (pubkey.pem). The second party, in a
pilot the operator, adds its own signature with this tool, using a key that
never leaves its machine. AIOpt then seals the pack, and the free verifier
(aiopt_verify.py) requires both signatures on every record, so neither party
alone can produce a record that verifies. It also writes your signed
statement of what you co-signed (record count, last record, ledger digest)
into the pack as cosign_statement.json, so anyone can check with the free
verifier that no record was removed after you signed.

This tool shares no code with AIOpt. Before it signs anything it re-derives
every hash and checks AIOpt's signature on every record, so you only co-sign
records that are intact. It writes a receipt that you keep: after sealing,
`check` confirms the sealed pack holds exactly the records you co-signed, none
removed.

Dependencies: `cryptography` (Ed25519) + Python stdlib. Nothing else.

Usage:
    python3 aiopt_cosign.py keygen my_cosign_key.pem
    python3 aiopt_cosign.py sign PACK_DIR --key my_cosign_key.pem [--yes] [--receipt FILE]
    python3 aiopt_cosign.py check PACK_DIR --receipt FILE

Exit code 0 = done; 1 = refused (a check failed); 2 = usage/IO error.
"""
import argparse
import base64
import hashlib
import json
import os
import sys
from collections import Counter
from pathlib import Path

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
except ImportError:
    sys.stderr.write("aiopt-cosign needs the 'cryptography' package: pip install cryptography\n")
    sys.exit(2)

ZERO_HASH = "0" * 64
RECEIPT_SCHEMA = "aiopt_cosign_receipt_v1"
STATEMENT_SCHEMA = "aiopt_cosign_statement_v1"


class Refused(Exception):
    """The pack failed a check; nothing was signed or written."""


def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def fingerprint(pub):
    return sha256_hex(pub.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))


def core_bytes(rec):
    return canon({k: rec[k] for k in ("seq", "timestamp", "kind", "payload", "prev_hash")})


def load_private_key(path):
    data = Path(path).read_bytes()
    try:
        key = serialization.load_pem_private_key(data, password=None)
    except TypeError:  # the key file is encrypted: ask for its passphrase
        import getpass
        phrase = getpass.getpass(f"Passphrase for {path}: ").encode("utf-8")
        key = serialization.load_pem_private_key(data, password=phrase)
    if not isinstance(key, Ed25519PrivateKey):
        raise Refused(f"{path} is not an Ed25519 key")
    return key


def keygen(path):
    p = Path(path)
    if p.exists():
        raise Refused(f"{p} already exists; not overwriting a key")
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption())
    p.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(pem)
    return fingerprint(key.public_key())


def read_unsealed(pack):
    """Check every record before anything is signed. Returns (records, AIOpt key)."""
    if (pack / "manifest.json").exists():
        raise Refused("this pack is already sealed; co-signing must happen before sealing")
    for name in ("ledger.jsonl", "pubkey.pem"):
        if not (pack / name).exists():
            raise Refused(f"{name} is missing from {pack}")
    system_pub = serialization.load_pem_public_key((pack / "pubkey.pem").read_bytes())
    if not isinstance(system_pub, Ed25519PublicKey):
        raise Refused("pubkey.pem is not an Ed25519 key")
    lines = (pack / "ledger.jsonl").read_text(encoding="utf-8").splitlines()
    records = [json.loads(x) for x in lines if x.strip()]
    if not records:
        raise Refused("the ledger is empty")
    prev = ZERO_HASH
    for i, rec in enumerate(records):
        if rec.get("seq") != i or rec.get("prev_hash") != prev:
            raise Refused(f"record {i}: the hash chain is broken")
        body = core_bytes(rec)
        if sha256_hex(body) != rec.get("record_hash"):
            raise Refused(f"record {i}: its hash does not match its content")
        try:
            system_pub.verify(base64.b64decode(rec["signature"]), body)
        except (InvalidSignature, KeyError, ValueError):
            raise Refused(f"record {i}: the signature from pubkey.pem does not verify")
        prev = rec["record_hash"]
    return records, system_pub


def summary(records):
    kinds = Counter(r["kind"] for r in records)
    verdicts = Counter(
        r["payload"].get("verdict") for r in records
        if isinstance(r.get("payload"), dict) and r["payload"].get("verdict"))
    lines = [f"  records: {len(records)}  "
             f"({records[0]['timestamp']} to {records[-1]['timestamp']})"]
    lines += [f"  kind {k}: {n}" for k, n in sorted(kinds.items())]
    lines += [f"  verdict {v}: {n}" for v, n in sorted(verdicts.items())]
    return "\n".join(lines)


def sign(pack, key_path, receipt_path=None, assume_yes=False, out=print):
    pack = Path(pack)
    records, system_pub = read_unsealed(pack)
    key = load_private_key(key_path)
    pub = key.public_key()
    if fingerprint(pub) == fingerprint(system_pub):
        raise Refused("your key is the same key that signed the records; "
                      "a co-signature must come from a different party")
    for i, rec in enumerate(records):
        if "actor_signature" in rec:
            try:
                pub.verify(base64.b64decode(rec["actor_signature"]), core_bytes(rec))
            except (InvalidSignature, ValueError):
                raise Refused(f"record {i} is already co-signed by a different key")

    out(f"Pack: {pack}\n{summary(records)}\n"
        f"  signed by key {fingerprint(system_pub)[:16]}...\n"
        f"  you co-sign with key {fingerprint(pub)[:16]}...")
    if not assume_yes:
        try:
            answer = input(f"Co-sign all {len(records)} records? [y/N] ").strip().lower()
        except EOFError:
            answer = ""
        if answer not in ("y", "yes"):
            raise Refused("not confirmed; nothing was signed")

    for rec in records:
        rec["actor_signature"] = base64.b64encode(key.sign(core_bytes(rec))).decode("ascii")
    body = "".join(json.dumps(r, sort_keys=True) + "\n" for r in records).encode("utf-8")
    tmp = pack / "ledger.jsonl.tmp"
    tmp.write_bytes(body)
    os.replace(tmp, pack / "ledger.jsonl")
    (pack / "pubkey_actor.pem").write_bytes(pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo))

    core = {
        "schema": RECEIPT_SCHEMA,
        "record_count": len(records),
        "head_hash": records[-1]["record_hash"],
        "ledger_sha256": sha256_hex(body),
        "pubkey_fingerprint": fingerprint(system_pub),
        "cosigner_fingerprint": fingerprint(pub),
    }
    # The same facts, signed again and left in the pack for any verifier: AIOpt
    # signs the manifest alone, so without this a shortened pack could be resealed.
    stmt = {**core, "schema": STATEMENT_SCHEMA}
    stmt["statement_signature"] = base64.b64encode(key.sign(canon(stmt))).decode("ascii")
    (pack / "cosign_statement.json").write_text(json.dumps(stmt, indent=2, sort_keys=True) + "\n")
    receipt = {**core, "receipt_signature": base64.b64encode(key.sign(canon(core))).decode("ascii")}
    rp = Path(receipt_path or f"aiopt_cosign_receipt_{core['head_hash'][:12]}.json")
    rp.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    out(f"Co-signed {len(records)} records. Receipt: {rp} (keep it; do not send it back)")
    return receipt


def check(pack, receipt_path, out=print):
    """Does the sealed pack hold exactly the ledger this receipt co-signed?"""
    pack = Path(pack)
    receipt = json.loads(Path(receipt_path).read_text())
    results = []

    def item(name, ok):
        results.append((name, bool(ok)))

    manifest_path = pack / "manifest.json"
    actor_path = pack / "pubkey_actor.pem"
    if not (manifest_path.exists() and actor_path.exists()):
        raise Refused("the pack is not sealed yet, or it is not a two-party pack")
    manifest = json.loads(manifest_path.read_text())
    actor_pub = serialization.load_pem_public_key(actor_path.read_bytes())
    core = {k: v for k, v in receipt.items() if k != "receipt_signature"}
    try:
        actor_pub.verify(base64.b64decode(receipt["receipt_signature"]), canon(core))
        item("receipt_signature", True)
    except (InvalidSignature, KeyError, ValueError):
        item("receipt_signature", False)
    item("cosigner_key", fingerprint(actor_pub) == receipt.get("cosigner_fingerprint"))
    item("same_record_count", manifest.get("record_count") == receipt.get("record_count"))
    item("same_head_hash", manifest.get("head_hash") == receipt.get("head_hash"))
    item("same_ledger", manifest.get("ledger_sha256") == receipt.get("ledger_sha256")
         and sha256_hex((pack / "ledger.jsonl").read_bytes()) == receipt.get("ledger_sha256"))
    stmt_path = pack / "cosign_statement.json"
    stmt = json.loads(stmt_path.read_text()) if stmt_path.exists() else {}
    stmt_core = {k: v for k, v in stmt.items() if k != "statement_signature"}
    try:
        actor_pub.verify(base64.b64decode(stmt["statement_signature"]), canon(stmt_core))
        signed = True
    except (InvalidSignature, KeyError, ValueError):
        signed = False
    item("your_statement_in_pack", signed and stmt_core.get("schema") == STATEMENT_SCHEMA and all(
        stmt_core.get(k) == receipt.get(k)
        for k in ("record_count", "head_hash", "ledger_sha256", "cosigner_fingerprint")))
    for name, ok in results:
        out(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    ok = all(passed for _, passed in results)
    out("RESULT: the sealed pack holds exactly the records you co-signed" if ok
        else "RESULT: FAILED, the sealed pack differs from what you co-signed")
    return ok


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keygen", help="create your co-signing key (Ed25519, file mode 600)")
    k.add_argument("key")
    s = sub.add_parser("sign", help="check every record, then co-sign them all")
    s.add_argument("pack")
    s.add_argument("--key", required=True, help="your co-signing key (PEM)")
    s.add_argument("--receipt", help="where to write your receipt (default: current directory)")
    s.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    c = sub.add_parser("check", help="compare a sealed pack with your receipt")
    c.add_argument("pack")
    c.add_argument("--receipt", required=True)
    args = ap.parse_args(argv)

    try:
        if args.cmd == "keygen":
            fp = keygen(args.key)
            print(f"Created {args.key} (fingerprint {fp}). Keep it on your side only.")
            return 0
        if not Path(args.pack).is_dir():
            sys.stderr.write(f"not a directory: {args.pack}\n")
            return 2
        if args.cmd == "sign":
            sign(args.pack, args.key, args.receipt, args.yes)
            return 0
        return 0 if check(args.pack, args.receipt) else 1
    except Refused as exc:
        print(f"REFUSED: {exc}")
        return 1
    except (OSError, ValueError) as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2


if __name__ == "__main__":
    sys.exit(main())
