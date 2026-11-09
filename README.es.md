# cortex9-authlib-jws-json-empty-signatures-model

Modelo diferencial offline de **CVE-2026-96760**: bucle vacuamente verdadero sobre signatures=[]. Educativo, offline y determinista.

English: [README.md](README.md).

Offline differential model of **CVE-2026-96760** (GHSA-6v38-4h7w-rj9h):
Authlib `JsonWebSignature.deserialize_json` accepted a JWS JSON object with
`signatures: []` because the verification loop set `is_valid = True` and
never ran. Educational, offline, deterministic.

Spanish: [README.es.md](README.es.md). Exercises: [PRACTICE.md](PRACTICE.md).

## Two semantics, always side by side

| | pre (`c529a61a`) | post (`6c11a02d`) |
|---|---|---|
| `signatures: []` | VALID (vacuous truth) | BadSignature |
| Diff | jws.py lines 205–214 | diff lines 5–12 |

## Run

```sh
PYTHONPATH=src python -m unittest discover -s tests -v
python scripts/derive_expected.py | diff - fixtures/expected.tsv
python scripts/gen_results.py /tmp/r && diff -r results /tmp/r
```

See [LIMITATIONS.md](LIMITATIONS.md) and [SOURCES.md](SOURCES.md).
License: Apache-2.0.
