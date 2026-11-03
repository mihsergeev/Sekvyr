"""Coordinator-run real-time projected-JWT soak; no control-plane mutation.

token_reader returns one actual UID/container-pinned file observation as
{token,pod_uid,container_id}. healthy must check a fresh source/read checkpoint,
same target data/revision and no extra app ReplicaSet, then return True. Every
fault factory is a bounded context manager which asserts unavailable/frozen
inside and restores its exact owned resources on exit. No callback runs here
until the live coordinator explicitly calls run().
"""

from contextlib import AbstractContextManager
from pathlib import Path
import re
import time

from panel_cases import observe_jwt, require, write_once


class TokenLifecycle:
    def __init__(self, panel_cases, token_reader, healthy, faults, operation_id="plain", *, _clock=None, _wall=None, _sleep=None):
        require(callable(token_reader) and callable(healthy) and isinstance(faults, (list, tuple)) and 2 <= len(faults) <= 8,
            "Stage7 soak requires explicit bounded lifecycle callbacks")
        require(re.fullmatch(r"[a-z][a-z0-9-]{0,39}", operation_id) is not None, "Stage7 soak operation invalid")
        require(all(isinstance(item, (list, tuple)) and len(item) == 2 and item[0] in ("sealed", "revoked")
            and callable(item[1]) for item in faults) and {item[0] for item in faults} == {"sealed", "revoked"},
            "Stage7 soak requires both approved fault kinds")
        self.panel, self.reader, self.healthy, self.faults = panel_cases, token_reader, healthy, tuple(faults)
        self.clock, self.wall, self.sleep = _clock or time.monotonic, _wall or time.time, _sleep or time.sleep
        self.real_clock = _clock is None and _wall is None and _sleep is None
        self.root = Path(panel_cases.root) / ("token-lifecycle-" + operation_id)
        self.root.mkdir(mode=0o700, exist_ok=True)
        require(not self.root.is_symlink() and self.root.resolve().parent == Path(panel_cases.root).resolve(), "Stage7 soak private scope invalid")

    def __repr__(self):
        return "<stage7 bounded projected-token lifecycle [redacted]>"

    def read(self):
        value = self.reader()
        require(isinstance(value, dict) and set(value) == {"token", "pod_uid", "container_id"}
            and isinstance(value["token"], str) and isinstance(value["pod_uid"], str)
            and isinstance(value["container_id"], str) and re.fullmatch(r"containerd://[0-9a-f]{64}", value["container_id"]),
            "Stage7 actual projected file observation invalid")
        token = value["token"].strip()
        observed = observe_jwt(token)
        require(observed["pod_uid"] == value["pod_uid"], "Stage7 projected token belongs to another Pod")
        return dict(value, token=token), observed

    def run(self, duration=600, interval=5, maximum_fault_seconds=60):
        require(type(duration) is int and 600 <= duration <= 1200 and type(interval) in (int, float) and 0 < interval <= 5
            and type(maximum_fault_seconds) is int and 1 <= maximum_fault_seconds <= 60, "Stage7 soak timing outside approved bounds")
        require(not (self.root / "started.json").exists(), "Stage7 soak cannot reset or silently resume its monotonic proof")
        try:
            initial, old = self.read()
            self.panel.exchange(initial["token"])
            require(old["exp"] > self.wall(), "Stage7 original JWT already expired")
            require(self.healthy() is True, "Stage7 initial fresh-health callback failed")
            started = self.clock()
            write_once(self.root / "started.json", {"pod_uid": initial["pod_uid"], "container_id": initial["container_id"],
                "tokenHash": old["hash"], "issuedAt": old["iat"], "expiresAt": old["exp"], "durationSeconds": duration,
                "faultKinds": [name for name, _ in self.faults], "realMonotonicClock": self.real_clock})
            authenticated_token, authenticated = initial["token"], old
            refreshes, health_checks, executed = 0, 1, 0

            def observation(authenticate):
                nonlocal authenticated_token, authenticated, refreshes
                value, claims = self.read()
                require(value["pod_uid"] == initial["pod_uid"] and value["container_id"] == initial["container_id"],
                    "Stage7 Pod/container restarted instead of projected-token refresh")
                require(claims["iat"] >= authenticated["iat"], "Stage7 projected token rolled back")
                if claims["hash"] != authenticated["hash"] and authenticate:
                    require(self.wall() < authenticated["exp"], "Stage7 refresh observation missed the old JWT expiry")
                    result = self.panel.assert_token_refresh(authenticated_token, value["token"])
                    require(result.get("samePodProjectedJWTRefreshed") is True, "Stage7 projected refresh was not authenticated")
                    authenticated_token, authenticated = value["token"], claims
                    refreshes += 1

            while True:
                elapsed = self.clock() - started
                require(0 <= elapsed <= duration + maximum_fault_seconds + interval + 10, "Stage7 monotonic soak exceeded bounded deadline")
                observation(True)
                require(self.healthy() is True, "Stage7 fresh health/no-extra-RS callback failed")
                health_checks += 1
                if executed < len(self.faults) and elapsed >= duration * (executed + 1) / (len(self.faults) + 1):
                    name, factory = self.faults[executed]
                    context = factory()
                    require(isinstance(context, AbstractContextManager), "Stage7 fault callback is not a context manager")
                    before = self.clock()
                    with context:
                        observation(False)
                    require(0 <= self.clock() - before <= maximum_fault_seconds, "Stage7 fault exceeded its approved bound")
                    observation(True)
                    require(self.healthy() is True, "Stage7 fault did not heal with fresh current data")
                    health_checks += 1
                    write_once(self.root / ("fault-" + str(executed) + ".json"), {"kind": name, "completed": True})
                    executed += 1
                if elapsed >= duration:
                    break
                self.sleep(min(interval, duration - elapsed))
            elapsed = self.clock() - started
            require(elapsed >= duration and executed == len(self.faults) and refreshes >= 1,
                "Stage7 real-duration soak or genuine projected refresh incomplete")
            result = {"production": False, "durationSeconds": int(elapsed), "realMonotonicClock": self.real_clock,
                "faultsExecuted": executed, "freshHealthChecks": health_checks, "authenticatedProjectedRefreshes": refreshes,
                "samePodUIDAndContainerID": True, "oldJWTStillValidDuringRefreshProof": True,
                "controlPlaneSignerMutated": False, "implicitJWKSRotationClaimed": False}
            write_once(self.root / "complete.json", result)
            return result
        except Exception:
            # Callback errors and JWTs may contain credentials. Only a fixed
            # reason escapes; the coordinator owns diagnostic/repair decisions.
            raise RuntimeError("Stage7 bounded token lifecycle did not complete") from None


def run(panel_cases, token_reader, healthy, faults, duration=600, interval=5, operation_id="plain"):
    return TokenLifecycle(panel_cases, token_reader, healthy, faults, operation_id).run(duration, interval)
