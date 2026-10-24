# Data

All test data in this repository is public known-answer test material. Nothing is synthetic
except where a test generates inputs from a seeded RNG (those are produced at test time and
never committed).

| File | Source | Pinned revision | SHA-256 | License |
|---|---|---|---|---|
| `vectors/acvp/keygen.json` | NIST ACVP-Server, `gen-val/json-files/ML-KEM-keyGen-FIPS203/internalProjection.json` (<https://github.com/usnistgov/ACVP-Server>) | commit `ad33b3d9504491767f1aa76382464f3b3fa2359e` (2026-07-28) | `d7a62a2c3476957f56dd8d24f9004ea6776ccfe995ffe71a65bb9506dc9c7b1b` | NIST public-service license (README "License" section): use, copy and distribute with the notice kept and NIST acknowledged as the source; NIST-employee work is not subject to US copyright |
| `vectors/acvp/encap-decap.json` | NIST ACVP-Server, `gen-val/json-files/ML-KEM-encapDecap-FIPS203/internalProjection.json` | same commit | `a556952ce869bb89c3a3196a701dad89647c193a34c86eafb61a9d710d5b810f` | as above |
| `vectors/xwing/test-vectors.json` | draft-connolly-cfrg-xwing-kem, `spec/test-vectors.json` (<https://github.com/dconnolly/draft-connolly-cfrg-xwing-kem>) | commit `5cb311dc7c7761c2b82d2f4a0037da2c2c7af8f3` (2024-10-20) | `409efe197550b22985b4a0419418a0c5f2c2b193426c55bd998399ec8d3e614d` | IETF Contribution under BCP 78/79 and the IETF Trust Legal Provisions (code components under the Simplified BSD License), per the repository's CONTRIBUTING.md |

Total committed vector data: about 2.0 MB.

## Contents

- **keyGen** — 75 AFT cases (25 per parameter set): inputs `d`, `z`; expected `ek`, `dk`.
- **encapDecap** — 165 cases:
  - 75 `encapsulation` AFT cases: inputs `ek`, `m`; expected `c`, `k`.
  - 30 `decapsulation` VAL cases: inputs `dk`, `c`; expected `k` (half are modified
    ciphertexts that must yield the implicit-rejection key).
  - 30 `encapsulationKeyCheck` cases: half carry coefficients `>= q` ("noisy linear
    system values too large") that the modulus check must reject.
  - 30 `decapsulationKeyCheck` cases: half have a modified `H(ek)` that the hash check must
    reject.
- **X-Wing** — 3 cases: `seed` (secret key), `eseed` (encapsulation randomness); expected
  `pk`, `ct`, `ss`.

## Provenance check

```sh
scripts/fetch-vectors.sh --verify-only   # offline: hash the committed files (part of make check)
scripts/fetch-vectors.sh                 # online: re-download from the pinned commits, then verify
```

The test harness also re-hashes every file against `vectors/SHA256SUMS` before reading it
(`hybridkem::kat::verify_checksums`), so a modified vector file fails the tests instead of
silently changing what "correct" means. CI runs the online fetch and requires
`git diff --exit-code -- vectors/` to be clean.

## Attribution

Known-answer vectors courtesy of the National Institute of Standards and Technology
(ACVP-Server). The files are unmodified copies; this repository adds only the checksum list.
