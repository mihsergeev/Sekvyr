"""Closed Stage 8 trial profiles; missing reviewed build pins deny all actions."""

from dataclasses import dataclass
import re

from app_modes import require

@dataclass(frozen=True)
class NodeProfile:
    name: str
    version: str
    node: str

_PROFILES = (
    NodeProfile("kind-1.37.0", "v1.37.0", "kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5"),
    NodeProfile("kind-1.34.11", "v1.34.11", "kindest/node:v1.34.11@sha256:44e222ee2132dab25ff87301682f89eb82c7880ea3a1bf543bfe9708fd08d67d"),
)
# Root fills measured reviewed build identities, never inferred from live state.
# No importer, creator or recovery is usable while any pin remains unset.
REVIEWED_ARTIFACTS = {
    "operator_image": "ghcr.io/mihsergeev/sekvyr-operator@sha256:ce947b4a3bc7a3d653f84e2c20d861f4ab648e09e70ea8a9eb7ca33150b52c76",
    "backend_image": "ghcr.io/mihsergeev/sekvyr-backend@sha256:28d194604745eb036e63f17df2edf543059804eaba7fd6f9b15a0e21eeb824c9",
    "recovery_sha256": "758540e5b720df65da5e5c14bbf2d22571789fe7b9f21bfea35f6f14197556b4",
    "provision_sha256": "be455d90d9d8c93d0ce93561ee0b33f5bc00c742b95aa398564357742209c2c2",
}
# Release versions of the pinned operator and backend images above.
OPERATOR_VERSION = "0.1.0-rc.4"
BACKEND_VERSION = "1.1.0-rc.7"
_RECEIPT_FORMAT = "sekvyr-stage8-kind-profile-v1"
PROFILE_RECEIPT = "stage8-profile.json"

def node_profile(name):
    require(type(name) is str, "Closed Stage 8 profile required")
    found = [p for p in _PROFILES if p.name == name]
    require(len(found) == 1, "Closed Stage 8 profile required")
    return found[0]

def reviewed_artifacts():
    require(set(REVIEWED_ARTIFACTS) == {"operator_image", "backend_image", "recovery_sha256", "provision_sha256"},
        "Reviewed Stage 8 artifact pins required")
    result = dict(REVIEWED_ARTIFACTS)
    for key in ("operator_image", "backend_image"):
        require(type(result[key]) is str and re.fullmatch(r"[a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64}", result[key]),
            "Reviewed Stage 8 immutable image required")
    for key in ("recovery_sha256", "provision_sha256"):
        require(type(result[key]) is str and re.fullmatch(r"[0-9a-f]{64}", result[key])
            and result[key] != "0" * 64, "Reviewed Stage 8 binary checksum required")
    require(result["operator_image"] != result["backend_image"], "Independent reviewed component images required")
    return result

def reviewed(name):
    return node_profile(name), reviewed_artifacts()

def receipt(profile, artifacts, root, task, root_creation_sha):
    require(profile == node_profile(profile.name) and artifacts == reviewed_artifacts()
        and re.fullmatch(r"[0-9a-f]{64}", root_creation_sha), "Exact Stage 8 profile receipt required")
    return {"format": _RECEIPT_FORMAT, "sourceStage": 8, "production": False,
        "profile": profile.name, "kubernetes": profile.version, "nodeImage": profile.node,
        "artifacts": artifacts, "operatorVersion": OPERATOR_VERSION, "backendVersion": BACKEND_VERSION,
        "rootTask": str(root), "runtimeTask": str(task), "rootCreationReceiptSHA256": root_creation_sha}
