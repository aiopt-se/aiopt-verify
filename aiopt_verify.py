#!/usr/bin/env python3
"""aiopt-verify: offline verifier for AIOpt evidence packs.

Verifies a pack (ledger.jsonl + manifest.json + pubkey.pem) with no trust in
AIOpt and no shared code with the writer: it re-derives every hash and checks
every Ed25519 signature itself. Any modification, deletion, or truncation of the
ledger fails.

A pack carries its own public keys, so on its own a pass shows only that the
pack is intact and signed by the keys inside it. To check WHO signed it, give
the key fingerprints you expect (from your contract or pilot agreement):
--expect-key for AIOpt's key, --expect-cosigner for the second party's key.
A pack re-signed with any other key then fails, and so does a two-party pack
cut down to one signature or shortened by one party alone.

Dependencies: `cryptography` (Ed25519) + Python stdlib. Nothing else.

Usage:
    python aiopt_verify.py /path/to/pack                      # intact? exit 0/1
    python aiopt_verify.py /path/to/pack --expect-key FP --expect-cosigner FP
    python aiopt_verify.py /path/to/pack --pins pins.json --json

pins.json: {"expect_key": [FP, ...], "expect_cosigner": [FP, ...],
            "require_two_party": true}
A fingerprint is the SHA-256 of the raw 32-byte public key, 64 hex characters;
this tool prints the fingerprints of every pack it checks.

Exit code 0 = every check passed; 1 = verification failed; 2 = usage/IO error.
"""
import argparse
import base64
import hashlib
import json
import re
import sys
from pathlib import Path

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.exceptions import InvalidSignature
except ImportError:
    sys.stderr.write("aiopt-verify needs the 'cryptography' package: pip install cryptography\n")
    sys.exit(2)

__version__ = "1.2.0"

SCHEMA = "aiopt_evidence_pack_v1"
STATEMENT_SCHEMA = "aiopt_cosign_statement_v1"
ZERO_HASH = "0" * 64
FINGERPRINT = re.compile(r"^[0-9a-f]{64}$")

# OpenTimestamps file header, then a version byte, then the hash of the stamped file
OTS_MAGIC = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"
OTS_SHA256 = 0x08


def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def fingerprint(pub):
    return sha256_hex(pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw))


def normalise_fingerprint(value):
    """A fingerprint as 64 lower-case hex characters, or ValueError."""
    fp = str(value).strip().lower()
    if not FINGERPRINT.match(fp):
        raise ValueError(f"not a key fingerprint (64 hex characters): {value!r}")
    return fp


def ots_file_digest(ots_bytes):
    """The SHA-256 an OpenTimestamps proof was made for, or None if unreadable."""
    head = len(OTS_MAGIC)
    if not ots_bytes.startswith(OTS_MAGIC) or len(ots_bytes) < head + 2 + 32:
        return None
    if ots_bytes[head] != 0x01 or ots_bytes[head + 1] != OTS_SHA256:
        return None
    return ots_bytes[head + 2:head + 34].hex()


def inspect_pack(pack_dir, expect_keys=(), expect_cosigners=(), require_two_party=False):
    """Check a pack. Returns a report dict:
    {"ok", "checks": [(name, passed, detail)], "warnings": [...], "keys": {...}}.
    """
    pack = Path(pack_dir)
    checks, warnings = [], []
    keys = {"aiopt_key": None, "cosigner_key": None}
    expect_keys = {normalise_fingerprint(k) for k in expect_keys}
    expect_cosigners = {normalise_fingerprint(k) for k in expect_cosigners}
    strict_two_party = bool(require_two_party or expect_cosigners)

    def check(name, passed, detail=""):
        checks.append((name, bool(passed), detail))
        return passed

    def report():
        return {"ok": all(passed for _, passed, _ in checks),
                "checks": checks, "warnings": warnings, "keys": keys}

    ledger_path = pack / "ledger.jsonl"
    manifest_path = pack / "manifest.json"
    pubkey_path = pack / "pubkey.pem"
    for f in (ledger_path, manifest_path, pubkey_path):
        if not check(f"present:{f.name}", f.exists(), str(f)):
            return report()

    manifest = json.loads(manifest_path.read_text())
    pub = serialization.load_pem_public_key(pubkey_path.read_bytes())

    check("schema", manifest.get("schema") == SCHEMA, manifest.get("schema", ""))

    # public-key fingerprint must match what the manifest was built against
    fp = fingerprint(pub)
    keys["aiopt_key"] = fp
    check("pubkey_fingerprint", fp == manifest.get("pubkey_fingerprint"),
          f"pack={fp[:16]}… manifest={str(manifest.get('pubkey_fingerprint'))[:16]}…")
    if expect_keys:
        check("pinned_key", fp in expect_keys,
              f"the pack is signed by {fp[:16]}…, which is not an expected key")

    # two-party packs carry a second (co-signer) key; every record must then
    # ALSO carry a valid co-signature, so neither party alone can forge one
    two_party = bool(manifest.get("two_party"))
    actor_pub = None
    if two_party:
        actor_path = pack / "pubkey_actor.pem"
        if check("present:pubkey_actor.pem", actor_path.exists(), str(actor_path)):
            actor_pub = serialization.load_pem_public_key(actor_path.read_bytes())
            afp = fingerprint(actor_pub)
            keys["cosigner_key"] = afp
            check("actor_pubkey_fingerprint",
                  afp == manifest.get("actor_pubkey_fingerprint"),
                  f"pack={afp[:16]}… manifest={str(manifest.get('actor_pubkey_fingerprint'))[:16]}…")
    if strict_two_party:
        # The manifest is signed by AIOpt's key only, so AIOpt's key alone could
        # rebuild a two-party pack as a single-party one. Only the verifier's
        # own expectation catches that.
        check("two_party_required", two_party and actor_pub is not None,
              "a co-signature was required, but this pack is signed by one party only")
    if expect_cosigners and keys["cosigner_key"] is not None:
        check("pinned_cosigner", keys["cosigner_key"] in expect_cosigners,
              f"the pack is co-signed by {keys['cosigner_key'][:16]}…, "
              "which is not an expected co-signer")

    # per-record: chain linkage, seq monotonicity, record hash, signature(s).
    # The ledger is read one line at a time, so a pack of any size verifies in
    # constant memory; the whole-file digest is built along the way.
    count, prev, head = 0, ZERO_HASH, ZERO_HASH
    parse_ok = chain_ok = seq_ok = rhash_ok = sig_ok = True
    actor_sig_ok = True
    digest = hashlib.sha256()
    with open(ledger_path, "rb") as fh:
        for line in fh:
            digest.update(line)
            if not line.strip():
                continue
            i = count
            count += 1
            try:
                rec = json.loads(line)
                core = {k: rec[k] for k in ("seq", "timestamp", "kind", "payload", "prev_hash")}
            except (ValueError, KeyError, TypeError):
                parse_ok = chain_ok = False
                continue
            if rec["prev_hash"] != prev:
                chain_ok = False
            if rec["seq"] != i:
                seq_ok = False
            core_bytes = canon(core)
            rh = sha256_hex(core_bytes)
            if rh != rec.get("record_hash"):
                rhash_ok = False
            try:
                pub.verify(base64.b64decode(rec["signature"]), core_bytes)
            except (InvalidSignature, Exception):
                sig_ok = False
            if actor_pub is not None:
                try:
                    actor_pub.verify(base64.b64decode(rec["actor_signature"]), core_bytes)
                except (InvalidSignature, KeyError, Exception):
                    actor_sig_ok = False
            prev = head = str(rec.get("record_hash"))
    ledger_sha = digest.hexdigest()
    check("record_count>0", count > 0, str(count))
    check("ledger_parse", parse_ok, "a line of ledger.jsonl is not a record")
    check("chain_linkage", chain_ok)
    check("seq_monotonic", seq_ok)
    check("record_hashes", rhash_ok)
    check("record_signatures", sig_ok)
    if two_party:
        check("actor_signatures", actor_sig_ok)

    # manifest anchors: count, head, whole-ledger digest. This is what catches
    # truncation (deleting the last record) that a plain chain would miss
    check("manifest_count", manifest.get("record_count") == count,
          f"manifest={manifest.get('record_count')} actual={count}")
    check("manifest_head", manifest.get("head_hash") == head)
    check("manifest_last_seq", manifest.get("last_seq") == (count - 1))
    check("ledger_digest", manifest.get("ledger_sha256") == ledger_sha)

    # the co-signer's own statement of what it signed: record count, head and
    # ledger digest, signed with its key. The manifest is AIOpt's alone, so this
    # is what stops AIOpt's key from dropping records from the end and re-sealing.
    if actor_pub is not None:
        statement_path = pack / "cosign_statement.json"
        if statement_path.exists():
            ok, detail = _check_statement(
                json.loads(statement_path.read_text()), actor_pub, fp,
                keys["cosigner_key"], count, head, ledger_sha)
            check("cosigner_statement", ok, detail)
        elif strict_two_party:
            check("cosigner_statement", False,
                  "cosign_statement.json is missing, so the co-signer's view of "
                  "the record count cannot be checked")
        else:
            warnings.append(
                "no co-signer statement (cosign_statement.json): an older pack. "
                "Every record is co-signed, but that records were not removed from "
                "the end before sealing rests on AIOpt's signature alone.")

    # manifest self-hash and signature. The two-party fields are part of the
    # signed core only when present, so this verifies both v1 single-party packs
    # (no such fields) and two-party packs without a schema bump.
    core_keys = ["schema", "created", "record_count", "first_seq", "last_seq",
                 "head_hash", "ledger_sha256", "pubkey_fingerprint"]
    if "two_party" in manifest:
        core_keys += ["two_party", "actor_pubkey_fingerprint"]
    core = {k: manifest[k] for k in core_keys}
    mhash = sha256_hex(canon(core))
    check("manifest_hash", mhash == manifest.get("manifest_hash"))
    try:
        pub.verify(base64.b64decode(manifest["manifest_signature"]),
                   manifest["manifest_hash"].encode("utf-8"))
        check("manifest_signature", True)
    except (InvalidSignature, Exception):
        check("manifest_signature", False)

    # an OpenTimestamps proof, if present, must be for THIS manifest. The proof
    # itself (the Bitcoin attestation) is checked with `ots verify`.
    hash_file, ots_path = pack / "manifest.hash", pack / "manifest.hash.ots"
    if hash_file.exists() or ots_path.exists():
        if check("anchor_hash_file", hash_file.exists() and
                 hash_file.read_text().strip() == manifest.get("manifest_hash"),
                 "manifest.hash does not hold this manifest's hash"):
            if ots_path.exists():
                check("anchor_proof_matches",
                      ots_file_digest(ots_path.read_bytes()) == sha256_hex(hash_file.read_bytes()),
                      "manifest.hash.ots was not made for this manifest.hash")

    if not expect_keys:
        warnings.append(
            "keys not pinned: this shows the pack is intact and signed by the keys "
            "it carries, not whose keys they are. Pass --expect-key (and "
            "--expect-cosigner) with the fingerprints from your agreement.")
    return report()


def _check_statement(stmt, actor_pub, aiopt_fp, cosigner_fp, count, head, ledger_sha):
    core = {k: v for k, v in stmt.items() if k != "statement_signature"}
    try:
        actor_pub.verify(base64.b64decode(stmt["statement_signature"]), canon(core))
    except (InvalidSignature, KeyError, Exception):
        return False, "the statement is not signed by the co-signer's key"
    expected = {"schema": STATEMENT_SCHEMA, "record_count": count, "head_hash": head,
                "ledger_sha256": ledger_sha, "pubkey_fingerprint": aiopt_fp,
                "cosigner_fingerprint": cosigner_fp}
    wrong = [k for k, v in expected.items() if core.get(k) != v]
    if wrong:
        return False, "the co-signer signed a different ledger: " + ", ".join(wrong)
    return True, ""


def verify_pack(pack_dir, **pins):
    """Return (ok: bool, checks: list[(name, passed, detail)])."""
    r = inspect_pack(pack_dir, **pins)
    return r["ok"], r["checks"]


def _load_pins(path):
    data = json.loads(Path(path).read_text())
    return (list(data.get("expect_key", [])), list(data.get("expect_cosigner", [])),
            bool(data.get("require_two_party", False)))


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pack", help="path to the evidence-pack directory")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--expect-key", action="append", default=[], metavar="FP",
                    help="fingerprint of the AIOpt key you expect (repeatable)")
    ap.add_argument("--expect-cosigner", action="append", default=[], metavar="FP",
                    help="fingerprint of the co-signer key you expect (repeatable); "
                         "implies --require-two-party")
    ap.add_argument("--require-two-party", action="store_true",
                    help="fail unless the pack is co-signed by a second party")
    ap.add_argument("--pins", metavar="FILE", help="JSON file with the same three settings")
    ap.add_argument("--version", action="version", version=f"aiopt-verify {__version__}")
    args = ap.parse_args()

    if not Path(args.pack).is_dir():
        sys.stderr.write(f"not a directory: {args.pack}\n")
        return 2
    expect_keys, expect_cosigners = list(args.expect_key), list(args.expect_cosigner)
    require_two_party = args.require_two_party
    try:
        if args.pins:
            k, c, r = _load_pins(args.pins)
            expect_keys += k
            expect_cosigners += c
            require_two_party = require_two_party or r
        r = inspect_pack(args.pack, expect_keys, expect_cosigners, require_two_party)
    except (OSError, ValueError) as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2

    ok = r["ok"]
    if args.json:
        print(json.dumps({
            "ok": ok,
            "verifier": f"aiopt-verify {__version__}",
            "keys": r["keys"],
            "checks": [{"name": n, "passed": p, "detail": d} for n, p, d in r["checks"]],
            "warnings": r["warnings"],
        }, indent=2))
    else:
        for name, passed, detail in r["checks"]:
            mark = "PASS" if passed else "FAIL"
            print(f"  [{mark}] {name}" + (f"  ({detail})" if detail and not passed else ""))
        print()
        if r["keys"]["aiopt_key"]:
            print(f"  AIOpt key (pubkey.pem):          {r['keys']['aiopt_key']}")
        if r["keys"]["cosigner_key"]:
            print(f"  Co-signer key (pubkey_actor.pem): {r['keys']['cosigner_key']}")
        for w in r["warnings"]:
            print(f"  WARNING: {w}")
        print()
        if not ok:
            print("RESULT: FAILED. The pack has been altered, truncated, or is not authentic")
        elif expect_keys:
            print("RESULT: VERIFIED. The pack is authentic and complete, signed by the expected key(s)")
        else:
            print("RESULT: VERIFIED. The pack is intact and complete; keys not pinned (see warning)")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
