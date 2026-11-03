"""Production Python opaque validators consume independent PUBLIC reader cases.

Encrypted payload attacks remain opaque to the panel. Actual reader rejection
is checked independently by Go and WebCrypto; no read key enters server code.
"""

import base64
import json
from pathlib import Path

import pytest

from app import e2e2, e2e2_rotation


PUBLIC = Path(__file__).resolve().parents[2] / "operator" / "tests" / "e2e2"


def read(name):
    return json.loads((PUBLIC / name).read_bytes())


@pytest.mark.parametrize("kind", ["snapshot", "wrapper"])
def test_public_per_layer_acceptance_preserves_panel_opacity(kind):
    matrix = read("public-layer-matrix.json")
    snapshots = read("public-snapshot-corpus.json")
    wrappers = read("public-reader-wrap-corpus.json")
    node = read("public-reader-wrap-vector.json")
    header = snapshots["cases"][0]["envelope"]["body"]["header"]
    expected_scope = {name: header[name] for name in e2e2.SCOPE}
    keys = {e2e2.key_id(e2e2.binary(snapshots["publisher_public_key"], 32)): snapshots["publisher_public_key"]}
    fingerprint = e2e2.node_fingerprint(base64.b64encode(e2e2.binary(node["node_public_key"], 65)).decode())
    cases = snapshots["cases"] if kind == "snapshot" else wrappers["cases"]
    denied = set(matrix[kind + "_panel_rejected"])
    assert len({case["name"] for case in cases}) == len(cases)
    assert denied <= {case["name"] for case in cases}
    accepted = opaque = 0
    for case in cases:
        raw = e2e2.canonical(case["envelope" if kind == "snapshot" else "wrapper"])
        def validate():
            if kind == "snapshot":
                return e2e2.validate_envelope(raw, expected_scope, keys)
            return e2e2.validate_wrapper(raw, expected_scope, fingerprint, keys)
        if case["name"] in denied:
            with pytest.raises(e2e2.Rejected):
                validate()
        else:
            validate()
            accepted += 1
            opaque += not case["valid"]
    assert {"total": len(cases), "reader_accepted": sum(case["valid"] for case in cases),
        "panel_accepted": accepted, "opaque_payload_accepted": opaque} == matrix["expected_counts"][kind]


AUTHORITY_CORPUS = read("public-authority-proof-corpus.json")


@pytest.mark.parametrize("case", AUTHORITY_CORPUS["cases"], ids=lambda case: case["name"])
def test_public_authority_v2_uses_independent_pin_and_layer_contract(case):
    corpus = AUTHORITY_CORPUS
    config = {"genesis_hash": corpus["genesis_hash"], "witness_public_key": corpus["pinned_witness"]["public_key"],
        "witness_epoch": corpus["witness_epoch"]}
    raw = e2e2.binary(case["raw_base64url"]) if "raw_base64url" in case else e2e2.canonical(case["proof"])
    def validate():
        return e2e2_rotation.validate_proof(raw, corpus["scope"], corpus["request_nonce"], corpus["floor"], config)
    if case["panel_valid"]:
        state = validate()
        assert state["scope"] == corpus["scope"]
        assert state["authority"]["witness_key"] == corpus["pinned_witness"]
    else:
        with pytest.raises(e2e2.Rejected):
            validate()
