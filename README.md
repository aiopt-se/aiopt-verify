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

A pack carries its own public keys, so this shows the pack is intact and signed
by the keys inside it. To check **who** signed it, pin the key fingerprints you
expect, for example the ones written into a pilot agreement:

```bash
python3 aiopt_verify.py PACK --expect-key <aiopt-key-fp> --expect-cosigner <your-key-fp>
python3 aiopt_verify.py PACK --pins pins.json
```

`pins.json` holds the same settings:

```json
{"expect_key": ["<64 hex>"], "expect_cosigner": ["<64 hex>"], "require_two_party": true}
```

A fingerprint is the SHA-256 of the raw 32-byte Ed25519 public key, as 64 hex
characters. Every report prints the fingerprints of the keys in the pack.
`--expect-cosigner` implies `--require-two-party`; both flags can be repeated
to accept more than one key (for example across a key rotation).

Exit code `0` = verified; `1` = altered/truncated/inauthentic; `2` = usage error.

No pack at hand? Generate one and verify it:

```bash
python3 make_sample_pack.py /tmp/demo
python3 aiopt_verify.py /tmp/demo/two_party
```

## What a pack contains

```
ledger.jsonl           append-only, Ed25519-signed, chain-hashed verdict records
manifest.json          manifest committing to record count, head hash and the
                       SHA-256 of the whole ledger, signed with pubkey.pem's key
pubkey.pem             public key of the system that wrote the records
                       (in a pilot, AIOpt's gate)
pubkey_actor.pem       (two-party packs) the second party's public key (in a
                       pilot, the operator); every record must ALSO carry a
                       valid signature from it
cosign_statement.json  (two-party packs) the second party's signed statement of
                       the record count, last record and ledger digest it
                       co-signed
manifest.hash(.ots)    (optional) the manifest hash and its OpenTimestamps proof
```

## What it detects

- **Modification** of any record: the record hash and its signature fail.
- **Deletion of a middle record**: the hash chain breaks and the count is short.
- **Deletion of the last record (truncation)**: the chain alone still looks
  valid, but the signed manifest's `record_count`, `head_hash` and
  `ledger_sha256` no longer match, and the manifest cannot be re-signed without
  the private key, which is not in the pack.
- **Single-party forgery in a two-party pack**: each record needs both
  signatures over the same canonical bytes; a stripped, wrong-key or re-signed
  record fails.
- **A two-party pack shortened by the first party alone**: the manifest is
  signed by the first key only, so its holder could drop records from the end
  and re-seal. The second party's statement no longer matches, and the check
  `cosigner_statement` fails.
- **With pinned keys** (`--expect-key`, `--expect-cosigner`):
  - a pack re-signed with any other key fails `pinned_key`;
  - a two-party pack rebuilt as a single-party pack by the first key's holder
    fails `two_party_required`;
  - a second key swapped for another fails `pinned_cosigner`.
- **A timestamp proof made for another manifest**: `manifest.hash` must hold
  this manifest's hash, and `manifest.hash.ots` must be a proof for that file.

## What it does NOT detect

- **Without pinned keys, who signed.** Anyone can build a self-consistent pack
  with their own key. The report says so in a warning until you pin keys.
- **Backdating**: the timestamp check above only ties the proof to this pack.
  Whether the proof is anchored in Bitcoin is checked with the `ots` CLI.
- **Records never exported**: the pack proves the record set is the one the
  keyholder(s) signed, not that every verdict ever made is in it, nor that a
  recorded verdict was correct.
- **Older two-party packs** (before 1.1) have no co-signer statement. They still
  verify, with a warning; with `--expect-cosigner` or `--require-two-party`
  they fail, because a shortened pack cannot be ruled out.

## Changes in 1.1

- `--expect-key`, `--expect-cosigner`, `--require-two-party` and `--pins`.
- The co-signer statement (`cosign_statement.json`) is checked when present
  and required when a co-signer is expected.
- `manifest.hash` and `manifest.hash.ots` are checked against the manifest.
- Key fingerprints are printed; `--json` adds `keys`, `warnings` and the
  verifier version. `--version`.
- Every 1.0 pack that verified still verifies without pins.

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
refuses a sealed pack and a key equal to the first signer's. It writes two
signed copies of what you co-signed (record count, last record, ledger digest):
`cosign_statement.json` into the pack, which any verifier checks, and a
receipt that you keep, which `check` compares with the sealed pack. Exit
codes: `0` done, `1` refused, `2` usage or file error.

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
