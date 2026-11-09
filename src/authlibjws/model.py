"""Offline model of Authlib JWS JSON empty-signatures bypass (CVE-2026-96760).

Ports the vacuous-truth loop in deserialize_json from
authlib/jose/rfc7515/jws.py at parent c529a61a (pre) and fix 6c11a02d (post).
Diff lines 5-12 of diffs/CVE-2026-96760_authlib_6c11a02da873.diff.

Signature cryptography is not performed: each entry in signatures[] is treated
as a validated header stub. The model only answers whether an empty or falsy
signatures list yields a successful verification.
"""
from __future__ import annotations
from dataclasses import dataclass


class BadSignatureError(Exception):
    pass


class DecodeError(Exception):
    pass


def _has_payload(obj: dict) -> bytes:
    if "payload" not in obj or obj["payload"] is None:
        raise DecodeError('Missing "payload" value')
    return str(obj["payload"]).encode()


def deserialize_json_pre(obj: dict) -> str:
    """Vacuous-truth loop (pre). Returns 'VALID' or raises."""
    _has_payload(obj)
    if "signatures" not in obj:
        raise DecodeError('Missing "signatures" value')
    headers = []
    is_valid = True
    # Real Python: iterating None raises TypeError. Empty list never enters the loop.
    sigs = obj["signatures"]
    if sigs is None:
        raise TypeError("'NoneType' object is not iterable")
    for header_obj in sigs:
        if not isinstance(header_obj, dict) or not header_obj.get("signature"):
            is_valid = False
            headers.append(None)
            continue
        headers.append(header_obj)
    if is_valid:
        return "VALID"
    raise BadSignatureError("invalid")


def deserialize_json_post(obj: dict) -> str:
    """Guarded loop (post): empty/falsy signatures => invalid."""
    _has_payload(obj)
    if "signatures" not in obj:
        raise DecodeError('Missing "signatures" value')
    headers = []
    is_valid = True
    # Diff: if not obj["signatures"]: is_valid = False
    if not obj["signatures"]:
        is_valid = False
    for header_obj in (obj["signatures"] or []):
        if not isinstance(header_obj, dict) or not header_obj.get("signature"):
            is_valid = False
            headers.append(None)
            continue
        headers.append(header_obj)
    if is_valid:
        return "VALID"
    raise BadSignatureError("invalid")


@dataclass(frozen=True)
class Case:
    id: str
    kind: str
    description: str
    obj: dict
    pre: str   # VALID / BadSignature / Decode
    post: str


def _run(fn, obj) -> str:
    try:
        return fn(obj)
    except BadSignatureError:
        return "BadSignature"
    except DecodeError:
        return "Decode"
    except TypeError:
        return "TypeError"


CASES = [
    Case("p01_empty_list", "pos", "signatures=[]",
         {"payload": "YQ", "signatures": []}, "VALID", "BadSignature"),
    Case("p02_null_signatures", "pos", "signatures=None: pre TypeError; post BadSignature (falsy guard)",
         {"payload": "YQ", "signatures": None}, "TypeError", "BadSignature"),
    Case("n01_one_valid", "neg", "one signature entry with signature field",
         {"payload": "YQ", "signatures": [{"protected": "eyJhbGciOiJIUzI1NiJ9", "signature": "sig"}]},
         "VALID", "VALID"),
    Case("n02_one_invalid", "neg", "one entry missing signature field",
         {"payload": "YQ", "signatures": [{"protected": "eyJhbGciOiJIUzI1NiJ9"}]},
         "BadSignature", "BadSignature"),
    Case("n03_mixed", "neg", "valid then invalid entry",
         {"payload": "YQ", "signatures": [
             {"protected": "a", "signature": "sig"},
             {"protected": "b"},
         ]}, "BadSignature", "BadSignature"),
    Case("n04_missing_payload", "neg", "no payload",
         {"signatures": []}, "Decode", "Decode"),
    Case("n05_two_valid", "neg", "two signature entries",
         {"payload": "YQ", "signatures": [
             {"protected": "a", "signature": "s1"},
             {"protected": "b", "signature": "s2"},
         ]}, "VALID", "VALID"),
]


def evaluate_case(case: Case) -> dict:
    pre = _run(deserialize_json_pre, case.obj)
    post = _run(deserialize_json_post, case.obj)
    ok = pre == case.pre and post == case.post
    flips = case.kind == "pos" and post == "BadSignature" and pre in ("VALID", "TypeError")
    return {
        "id": case.id, "kind": case.kind, "description": case.description,
        "pre": pre, "post": post, "expected_pre": case.pre, "expected_post": case.post,
        "ok": ok, "flips": flips,
    }
