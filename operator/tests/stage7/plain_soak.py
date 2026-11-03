"""Concrete coordinator callbacks for the real Plain/projected-token soak."""

from contextlib import contextmanager

from app_modes import require, wait
from token_lifecycle import run as token_run


def run(cases):
    p, apps = cases.installation, cases.apps
    names = (cases.env_name, cases.volume_name, cases.agent_name)
    baseline = {name: apps.capture(name) for name in names}
    reference = apps.target(p.target_ref())
    target_uid = reference["metadata"]["uid"]
    target_data = reference["data"]
    revision = reference["metadata"]["annotations"]["secrets.sekvyr.ru/revision"]

    def frozen():
        target = apps.target({"name": reference["metadata"]["name"], "uid": target_uid})
        require(target["metadata"]["uid"] == target_uid and target["data"] == target_data
            and target["metadata"]["annotations"]["secrets.sekvyr.ru/revision"] == revision,
            "Soak changed last good Plain target")
        for name in names:
            apps.frozen(name, baseline[name], seconds=0)
        return True

    def healthy():
        previous = p.owned.get("SekvyrSecret", p.cr_name).get("status", {}).get("lastSuccessfulSyncTime")
        cases.poke()
        wait(lambda: p.current(after_success=previous), timeout=35)
        p.target_ref(cases.selected["generation"], cases.selected["demo"], after_success=previous)
        return frozen()

    def unavailable():
        value = p.owned.get("SekvyrSecret", p.cr_name)
        generation = value["metadata"]["generation"]
        return any(condition.get("type") == "DataCurrent" and condition.get("status") == "False"
            and condition.get("observedGeneration") == generation for condition in value.get("status", {}).get("conditions", []))

    @contextmanager
    def fault(kind):
        @contextmanager
        def revoked():
            cases.provider.revoke()
            try:
                yield
            finally:
                cases.provider.restore()

        with (cases.provider.sealed() if kind == "sealed" else revoked()):
            cases.poke()
            wait(unavailable, timeout=30)
            frozen()
            yield
        # The generic lifecycle calls healthy immediately after the context.

    result = token_run(cases.agent_provider, cases.token, healthy,
        [(kind, lambda kind=kind: fault(kind)) for kind in ("sealed", "revoked", "sealed", "revoked")],
        duration=600, interval=5, operation_id="plain-real")
    return cases.proof("plain-token-soak", dict(result, repeatedOperatorSourceFailuresFrozen=True,
        projectedReaderUsesSeparateAgentIdentity=True, allThreeApplicationProcessesUnchanged=True))
