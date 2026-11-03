"""Signer rollover ONLY for the explicit same-host remote kind capability.

Crypto, two-flag mutation, original-key hashes and authenticated JWKS probes are
the reviewed shared implementation. This replaces no WSL ownership validator.
"""

from app_modes import require
from kind_jwks import KindJWKS
from remote_kind_capability import Capability


class RemoteKindJWKS(KindJWKS):
    def __init__(self, cluster, capability_path):
        self.capability = Capability(cluster)
        require(capability_path == self.capability.marker, "Explicit same-host remote kind capability path required")
        self.cluster, self.task = cluster, self.capability.task
        self.pin_file, self.pin_raw, self.pin = self.capability.pin_file, self.capability.pin_raw, self.capability.pin
        self.native = self.capability.backup
        self.creation_receipt, self.creation_raw = self.native / "creation.json", self.capability.creator_raw
        self.root = self.task / "private" / "kind-jwks"
        self.root.mkdir(mode=0o700, exist_ok=True)
        require(not self.root.is_symlink(), "Remote signer directory symlink refused")
        self.prepared = False

    def guard(self):
        self.capability.guard()

    def _exec(self, *args, data=None):
        return self.capability.exec(*args, data=data)

    def __repr__(self):
        return "<creator-pinned same-host remote kind JWKS [redacted]>"
