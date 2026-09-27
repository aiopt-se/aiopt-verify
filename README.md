# aiopt-verify

Offline verifier for **AIOpt evidence packs**. Given a pack (an approvals-and-
refusals record from an operator's network-change gate), it re-derives every
hash and checks every signature itself, and reports whether the pack is
authentic and complete. It shares no code with the system that writes the
records.

Standalone, MIT-licensed tools: one file to verify (`aiopt_verify.py`), one
file for the second party to co-sign a pack with its own key
(`aiopt_cosign.py`), one file that doubles as an executable spec of the pack
format (`make_sample_pack.py`), and their tests.

## Install

Requires Python 3 and the `cryptography` package.

```bash
pip install cryptography     # the only dependency; everything else is stdlib
```

## Use

```bash
python3 aiopt_verify.py /path/to/evidence-pack        # human report
python3 aiopt_verify.py /path/to/evidence-pack --json # machine-readable
```

Exit code `0` = verified; `1` = altered/truncated/inauthentic; `2` = usage error.

No pack at hand? Generate one and verify it:

```bash
python3 make_sample_pack.py /tmp/demo
python3 aiopt_verify.py /tmp/demo/two_party
```

## What a pack contains

```
ledger.jsonl       append-only, Ed25519-signed, chain-hashed verdict records
manifest.json      signed manifest committing to record count, head hash, and
                   the SHA-256 of the whole ledger
pubkey.pem         the public key that signed every record and the manifest
pubkey_actor.pem   (two-party packs) the second party's public key; every
                   record must ALSO carry a valid signature from it
anchor.* / *.ots   (optional) an external-clock proof of the manifest hash
```

## What it detects

- **Modification** of any record → the record hash and its signature fail.
- **Deletion of a middle record** → the hash chain breaks and the count is short.
- **Deletion of the last record (truncation)** → the chain alone still looks
  valid, but the signed manifest's `record_count`, `head_hash`, and
  `ledger_sha256` no longer match, and the manifest cannot be re-signed without
  the private key behind `pubkey.pem`, which is not in the pack.
- **Single-party forgery in a two-party pack** → each record needs both
  signatures over the same canonical bytes; a stripped, wrong-key, or re-signed
  record fails. Neither party alone can produce a valid record.

## What it does NOT detect

- **Backdating**: nothing in the pack proves *when* it was created. Optional
  external-clock anchoring (OpenTimestamps over the manifest hash) closes this;
  verify the `.ots` proof with the `ots` CLI separately.
- **A dishonest writer at record time**: the pack proves the record set is the
  one the keyholder(s) signed, not that a recorded verdict was correct.
- **Records left out at sealing**: whoever holds the sealing key could drop the
  last records and seal again, and the remaining records would still verify.
  The co-signer's receipt catches this (`aiopt_cosign.py check`, below).

The public key must be obtained through a trusted channel (e.g. the operator's
published key fingerprint).

## Co-signing a pack (the second party)

In a two-party pack, the second party (in a pilot, the operator) adds its own
signature to every record with a key that never leaves its machine. AIOpt
exports the pack unsealed, the second party co-signs it, and AIOpt seals it.

```bash
python3 aiopt_cosign.py keygen my_cosign_key.pem                 # once
python3 aiopt_cosign.py sign PACK_DIR --key my_cosign_key.pem     # checks, then co-signs
python3 aiopt_cosign.py check SEALED_PACK --receipt RECEIPT.json  # after sealing
```

Before it signs anything, the tool re-derives every hash and checks the first
signature on every record, so you only co-sign records that are intact. It
refuses a sealed pack and a key equal to the first signer's. It writes a signed
receipt that you keep: after sealing, `check` confirms the sealed pack holds
exactly the records you co-signed, none removed. Exit codes: `0` done, `1`
refused, `2` usage or file error.

## Tests

```bash
pip install cryptography pytest
pytest    # clean packs verify, every tamper fails; the co-signer refuses bad packs
```

The tests build packs with `make_sample_pack.py` (written independently of the
platform's pack writer), so passing them also demonstrates that two independent
implementations of the format agree.

## License

MIT. See [LICENSE](LICENSE).
