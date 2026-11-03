"""Stage 8 rollover with unchanged two-flag/crypto/restore algorithms."""

from .capability import Capability, fixed_function
from .profiles import reviewed
import remote_kind_jwks as legacy

class RemoteKindJWKS(legacy.RemoteKindJWKS):
    def __init__(self, cluster, capability_path, *, profile):
        selected, _ = reviewed(profile)
        fixed_function(legacy.RemoteKindJWKS.__init__,
            Capability=lambda value: Capability(value, profile=selected.name))(self, cluster, capability_path)

    def __repr__(self):
        return "<Stage 8 creator-pinned remote kind JWKS [redacted]>"
