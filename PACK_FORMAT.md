# AIOpt evidence pack: format specification

Version 1.1, 28 September 2026. Schema `aiopt_evidence_pack_v1`. This page is
enough to write an independent verifier; `make_sample_pack.py` is the same
specification as code, and `aiopt_verify.py` is one verifier of it.

## 1. What a pack is

A directory that holds a record of gate decisions (approvals and refusals of
proposed network changes), signed so that any change to the record after
signing can be detected by anyone, offline, without trusting the party that
wrote it. A pack proves that its records are the ones the keyholder(s) signed,
in that order, with nothing removed. It does not prove that a decision was
right, nor that every decision ever made is in it.

## 2. Files

| File | Required | Content |
|---|---|---|
| `ledger.jsonl` | yes | one JSON object per line: the records, in order |
| `manifest.json` | yes | a summary of the whole ledger, signed by the writer's key |
| `pubkey.pem` | yes | the writer's Ed25519 public key (PEM, SubjectPublicKeyInfo) |
| `pubkey_actor.pem` | two-party packs | the second party's Ed25519 public key |
| `cosign_statement.json` | two-party packs since 1.1 | the second party's signed statement of what it co-signed |
| `manifest.hash`, `manifest.hash.ots` | optional | the manifest hash as text, and its OpenTimestamps proof |
| `aiopt_verify.py`, `LICENSE` | recommended | a verifier (MIT), for convenience only |
| `README.txt` | recommended | contents and how to verify |

Any other file is ignored by verification.

## 3. Encoding rules

- **Canonical JSON:** `json.dumps(obj, sort_keys=True, separators=(",", ":"))`
  encoded as UTF-8: keys sorted, no spaces, no NaN or infinity. Every hash and
  signature below is over canonical JSON of the stated fields, and nothing else.
- **Hash:** SHA-256, written as 64 lower-case hex characters.
- **Signature:** Ed25519 over the stated bytes, written as standard base64.
- **Key fingerprint:** SHA-256 of the raw 32-byte Ed25519 public key.
- **Timestamps:** ISO 8601 text. They are data, not proof of time.

## 4. Records (`ledger.jsonl`)

Each line is one record with exactly these fields:

| Field | Type | Meaning |
|---|---|---|
| `seq` | integer | position in the ledger, 0 for the first record, then +1 |
| `timestamp` | string | when the record was made, as the writer states it |
| `kind` | string | what the record is, for example `countersign_verdict`, `replay_run`, `replay_verdict` |
| `payload` | object | the decision itself; its content depends on `kind` |
| `prev_hash` | string | `record_hash` of the previous record; 64 zeros for the first |
| `record_hash` | string | SHA-256 of the canonical JSON of the **core**: `seq`, `timestamp`, `kind`, `payload`, `prev_hash` |
| `signature` | string | Ed25519 signature by the writer's key over the same core bytes |
| `actor_signature` | string | two-party packs only: signature by the second party over the same core bytes |

The chain (`prev_hash`) ties each record to the one before it; the manifest
ties the last record and the whole file to the writer's key. Editing a record
breaks its hash and its signature; removing a record from the middle breaks
the chain; removing the last record is caught by the manifest.

## 5. Manifest (`manifest.json`)

| Field | Type | Meaning |
|---|---|---|
| `schema` | string | `aiopt_evidence_pack_v1` |
| `created` | string | when the pack was sealed, as the writer states it |
| `record_count` | integer | number of records |
| `first_seq`, `last_seq` | integer | `seq` of the first and last record |
| `head_hash` | string | `record_hash` of the last record |
| `ledger_sha256` | string | SHA-256 of `ledger.jsonl` byte for byte |
| `pubkey_fingerprint` | string | fingerprint of the key in `pubkey.pem` |
| `two_party` | boolean | present in packs written since two-party support; true when every record must also carry `actor_signature` |
| `actor_pubkey_fingerprint` | string or null | fingerprint of `pubkey_actor.pem`, present with `two_party` |
| `manifest_hash` | string | SHA-256 of the canonical JSON of all fields above |
| `manifest_signature` | string | Ed25519 signature by the writer's key over the UTF-8 text of `manifest_hash` |

Older single-party packs omit `two_party` and `actor_pubkey_fingerprint`; a
verifier includes them in the hashed field set only when present.

## 6. Co-signer statement (`cosign_statement.json`)

The manifest is signed by the writer's key alone, so the writer could drop
records from the end of a co-signed ledger and seal again; every remaining
record would still carry both signatures. The second party therefore leaves its
own statement in the pack:

| Field | Meaning |
|---|---|
| `schema` | `aiopt_cosign_statement_v1` |
| `record_count`, `head_hash`, `ledger_sha256` | the ledger as it was when co-signed |
| `pubkey_fingerprint` | the writer's key fingerprint |
| `cosigner_fingerprint` | the second party's key fingerprint |
| `statement_signature` | Ed25519 by the second party over the canonical JSON of all fields above |

The second party also keeps a receipt with the same fields outside the pack.

## 7. Verification, in order

1. The three required files exist; `schema` matches.
2. The fingerprint of `pubkey.pem` equals `pubkey_fingerprint`. If keys are
   pinned, it is one of the expected writer keys.
3. If `two_party`: `pubkey_actor.pem` exists and its fingerprint equals
   `actor_pubkey_fingerprint`; if pinned, it is an expected co-signer key. If a
   co-signer is expected and the pack is single-party, fail.
4. For each record in file order: `prev_hash` equals the previous
   `record_hash` (zeros first); `seq` equals its position; `record_hash` equals
   the SHA-256 of its canonical core; `signature` verifies with the writer's
   key; in a two-party pack `actor_signature` verifies with the second key.
5. `record_count`, `head_hash`, `last_seq` and `ledger_sha256` match the file.
6. In a two-party pack: `cosign_statement.json` verifies with the second key
   and matches the ledger (count, head, digest, both fingerprints). Missing:
   warn, or fail when a co-signer is expected.
7. `manifest_hash` equals the SHA-256 of the manifest's canonical core;
   `manifest_signature` verifies with the writer's key.
8. If present, `manifest.hash` holds `manifest_hash`, and `manifest.hash.ots`
   is a proof for that file (the file hash follows the OpenTimestamps header).
   Whether the proof reaches Bitcoin is checked separately with `ots verify`.

Any failure fails the pack. A pass without pinned keys shows only that the
pack is intact and signed by the keys it carries; who those keys belong to
comes from outside the pack, for example a fingerprint written into a
contract.

## 8. What is deliberately not in the format

No encryption (a pack is a record, not a secret), no key rotation inside a
pack (rotate by sealing a new pack), no proof of completeness across packs
(the operator's own records and the co-signer's receipts cover that), and no
timestamp authority beyond the optional OpenTimestamps proof.
