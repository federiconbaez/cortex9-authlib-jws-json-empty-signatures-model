# Limitations

- **Loop validity only.** Cryptographic verification of each signature entry
  is stubbed: presence of a `signature` field counts as valid.
- **Flattened JWS** (no `signatures` key) is out of scope for this CVE.
- `signatures: null` under pre raises TypeError in real Python; modelled
  explicitly. The GHSA/NVD case is the empty list.
- This is not a finding. Nothing is attributed beyond SOURCES.md and the CVE.
