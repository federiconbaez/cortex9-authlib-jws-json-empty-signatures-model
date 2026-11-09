# Sources

Local copies under `security-research-45/sources/cve2026/`. Advisory:
GHSA-6v38-4h7w-rj9h. CVE: CVE-2026-96760.

| Source | Used for | SHA-256 of copy |
|---|---|---|
| NVD / GHSA JSON | ID + versions ≤1.8.0 → 1.9.0 | see SHA256SUMS |
| commit `6c11a02da8730914cea08ec195f1108a40dc6733` diff | the fix | `928fe4cb28dd0b54f3551796092b61177836b5127759e564f10584c5c7c4144c` |
| `jws.py` at parent `c529a61a` | pre | `89b282aa8c555a3b91c8dba6cad898f0a474af6d50c8e9d23ba3aa468369b6d7` |
| `jws.py` at `6c11a02d` | post | `b0a4318e13c6bafbaf893a4413a9b0ddeca45b5ec6c898eb0b1cc72074e3f7f4` |

No source contained instructions addressed to a tool or agent.
