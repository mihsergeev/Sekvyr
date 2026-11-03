"""Require a new authenticated synchronization after a completed Helm rollout.

The caller establishes Ready replicas and physical absence of the old owned
fencer Pods before recording cutover and the baseline status timestamp. This
observer never treats an unchanged, previously successful status as fresh.
"""

from datetime import datetime, timezone
import re
import time


def _require(value):
    if not value:
        raise RuntimeError("Fresh Helm synchronization proof is invalid")


def _timestamp(value):
    _require(isinstance(value, str) and re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)", value))
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise RuntimeError("Fresh Helm synchronization timestamp is invalid") from None


class _FreshSyncStatus:
    def __init__(self, app, snapshot, *, cutover, baseline_last_success,
                 expected_cr_generation, expected_store_uid,
                 expected_store_generation,
                 cr_name="runtime", store_name="application-secrets"):
        _require(isinstance(cutover, datetime) and cutover.tzinfo is not None and
                 cutover.utcoffset() == timezone.utc.utcoffset(cutover))
        _require(type(expected_cr_generation) is int and expected_cr_generation > 0 and
                 type(expected_store_generation) is int and expected_store_generation > 0)
        _require(isinstance(expected_store_uid, str) and bool(expected_store_uid))
        _require(isinstance(snapshot, dict) and isinstance(snapshot.get("sequence"), str) and
                 re.fullmatch(r"[1-9][0-9]{0,19}", snapshot["sequence"]) and
                 isinstance(snapshot.get("envelope_hash"), str) and
                 re.fullmatch(r"[0-9a-f]{64}", snapshot["envelope_hash"]))
        self.app, self.cutover = app, cutover
        self.baseline = _timestamp(baseline_last_success)
        _require(self.baseline <= cutover)
        self.cr_name, self.store_name = cr_name, store_name
        self.cr_generation = expected_cr_generation
        self.store_uid, self.store_generation = expected_store_uid, expected_store_generation
        self.checkpoint = {"sequence": snapshot["sequence"], "envelopeHash": snapshot["envelope_hash"]}

    def current(self):
        # app.get performs the fixture's original creation-UID ownership checks.
        cr = self.app.get("SekvyrSecret", self.cr_name)
        store = self.app.get("SekvyrStore", self.store_name)
        metadata, status = cr["metadata"], cr.get("status", {})
        _require(not metadata.get("deletionTimestamp") and
                 metadata.get("generation") == self.cr_generation and
                 store["metadata"].get("uid") == self.store_uid and
                 store["metadata"].get("generation") == self.store_generation and
                 not store["metadata"].get("deletionTimestamp"))
        _require(cr.get("spec", {}).get("storeRef") == {"name": self.store_name, "uid": self.store_uid})
        _require(not cr.get("spec", {}).get("suspend", False))
        if (status.get("observedGeneration") != self.cr_generation or
                status.get("observedStoreUID") != self.store_uid or
                status.get("observedStoreGeneration") != self.store_generation or
                status.get("lastVerifiedCheckpoint") != self.checkpoint):
            return False
        conditions = status.get("conditions", [])
        if not isinstance(conditions, list) or any(not isinstance(item, dict) for item in conditions):
            return False
        named = {item.get("type"): item for item in conditions}
        if len(named) != len(conditions) or any(
                named.get(name, {}).get("status") != "True" or
                named[name].get("observedGeneration") != self.cr_generation
                for name in ("Ready", "BootstrapReady", "WitnessReady", "DataCurrent", "RolloutReady")):
            return False
        success, attempt = status.get("lastSuccessfulSyncTime"), status.get("lastAttemptTime")
        if success is None or attempt is None:
            return False
        success_time, attempt_time = _timestamp(success), _timestamp(attempt)
        return cr if success_time == attempt_time and success_time > self.baseline and success_time >= self.cutover else False

    def wait(self, *, timeout=240, poke=False):
        _require(type(timeout) in (int, float) and 0 < timeout <= 600 and type(poke) is bool)
        if poke:
            # The application helper uses the original UID/RV guarded annotation
            # patch; it changes no CR spec or source generation.
            self.app.poke()
        deadline = time.monotonic() + timeout
        while True:
            result = self.current()
            if result:
                return result
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError("Fresh Helm synchronization was not observed")
            time.sleep(min(1, remaining))


class FreshHelmSync(_FreshSyncStatus):
    """Diagnostic/image upgrade: physical OLD fencer absence is mandatory."""
    def __init__(self, app, snapshot, *, cutover, baseline_last_success,
                 expected_cr_generation, expected_store_uid,
                 expected_store_generation, old_owned_fencers_absent,
                 cr_name="runtime", store_name="application-secrets"):
        _require(old_owned_fencers_absent is True)
        super().__init__(app, snapshot, cutover=cutover, baseline_last_success=baseline_last_success,
            expected_cr_generation=expected_cr_generation, expected_store_uid=expected_store_uid,
            expected_store_generation=expected_store_generation, cr_name=cr_name, store_name=store_name)
