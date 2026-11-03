"""Stage 8 creator provenance over unchanged Stage 7 ownership algorithms."""

from pathlib import Path
from types import FunctionType

from app_modes import require
from .profiles import PROFILE_RECEIPT, receipt, reviewed
import remote_kind_capability as legacy

def fixed_function(function, **overrides):
    """Copy only a reviewed function's globals; never patch the source module."""
    require(set(overrides).issubset(function.__globals__), "Unreviewed function-scope override")
    copy = FunctionType(function.__code__, dict(function.__globals__, **overrides),
        function.__name__, function.__defaults__, function.__closure__)
    copy.__kwdefaults__ = function.__kwdefaults__
    return copy

class Capability(legacy.Capability):
    def __init__(self, cluster, *, profile):
        self.profile, self.artifacts = reviewed(profile)  # Before file/Docker actions.
        self.stage8_raw = None
        task = Path(cluster.task)
        marker_raw, marker = legacy.read(task / "private" / legacy.MARKER, 8192)
        require(marker.get("format") == legacy.FORMAT and marker.get("runtimeTask") == str(task),
            "Stage 8 runtime marker scope differs")
        root, runtime, backup = legacy.paths(marker["rootTask"], marker["runtimeTask"])
        require(runtime == task, "Stage 8 runtime directory differs")
        for path in (root, runtime, backup):
            legacy.directory(path)
        preflight_raw, preflight = legacy.read(backup / "preflight.json", 1 << 20)
        require(legacy.digest(preflight_raw) == marker.get("preflightSHA256"),
            "Stage 8 marker does not pin preflight")
        self.root, self.task, self.preflight = root, runtime, preflight
        self._stage8_guard()
        self.initial_marker_raw = marker_raw
        fixed_function(legacy.Capability.__init__, NODE=self.profile.node)(self, cluster)

    def _stage8_guard(self):
        expected = receipt(self.profile, self.artifacts, self.root, self.task,
            self.preflight["rootCreationReceiptSHA256"])
        path = self.root / "receipts" / PROFILE_RECEIPT
        raw, actual = legacy.read(path, 8192)
        require(actual == expected and self.preflight.get("stage8ProfileSHA256") == legacy.digest(raw),
            "Stage 8 profile differs from exclusive creator preflight")
        if self.stage8_raw is not None:
            require(raw == self.stage8_raw, "Stage 8 profile receipt changed")
        self.stage8_path, self.stage8_raw = path, raw

    def guard(self):
        # Parent __init__ has set root/task/preflight before its self.guard().
        require(legacy.read(self.marker, 8192)[0] == self.initial_marker_raw == self.raw,
            "Stage 8 capability marker changed")
        self._stage8_guard()
        identity = fixed_function(legacy.node_identity, NODE=self.profile.node)
        return fixed_function(legacy.Capability.guard, NODE=self.profile.node, node_identity=identity)(self)

    def root_plan(self):
        self._stage8_guard()
        return {**super().root_plan(), "stage8ProfilePath": str(self.stage8_path),
            "stage8ProfileSHA256": legacy.digest(self.stage8_raw)}
