"""Bounded anonymous TLS health timing for creation-pinned trial fencer Pods."""

import json
import ssl
import time
import urllib.error
import urllib.request

from app_modes import OwnedNamespace, require
from fixture import canonical, write_private
from forward import Forward


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def observe(coordinator):
    c = coordinator
    scope = OwnedNamespace(c.cluster, c.namespaces["apps"])
    result, identities = {"roles": {}, "fencerHTTPSamples": [], "currentPodEvents": [], "production": False}, {}
    fencers = []
    for role in ("operator", "fencer"):
        deployment = scope.get("Deployment", "stage6-" + role)
        selectors = deployment["spec"]["selector"]
        require(set(selectors) == {"matchLabels"}, "Probe observer requires one exact selector")
        labels = ",".join(key + "=" + value for key, value in sorted(selectors["matchLabels"].items()))
        sets = json.loads(c.cluster.kube("get", "replicasets", "-n", scope.namespace, "-l", labels, "-o", "json").stdout)["items"]
        require(all(any(ref.get("kind") == "Deployment" and ref.get("uid") == deployment["metadata"]["uid"] for ref in value["metadata"].get("ownerReferences", [])) for value in sets), "Probe ReplicaSet ownership differs")
        rs_uids = {value["metadata"]["uid"] for value in sets}
        pods = json.loads(c.cluster.kube("get", "pods", "-n", scope.namespace, "-l", labels, "-o", "json").stdout)["items"]
        active = [value for value in pods if not value["metadata"].get("deletionTimestamp")]
        require(len(active) == 2 and all(any(ref.get("kind") == "ReplicaSet" and ref.get("uid") in rs_uids for ref in value["metadata"].get("ownerReferences", [])) for value in active), "Probe Pod ownership differs")
        probes = [value["readinessProbe"] for value in deployment["spec"]["template"]["spec"]["containers"]]
        result["roles"][role] = {"readyReplicas": deployment.get("status", {}).get("readyReplicas", 0),
            "readinessProbes": [{"path": value.get("httpGet", {}).get("path"), "scheme": value.get("httpGet", {}).get("scheme", "HTTP"),
                "timeoutSeconds": value.get("timeoutSeconds", 1), "periodSeconds": value.get("periodSeconds", 10),
                "failureThreshold": value.get("failureThreshold", 3)} for value in probes],
            "containerRestartsSincePodCreation": [status["restartCount"] for value in active for status in value["status"].get("containerStatuses", [])]}
        for pod in active:
            identities[pod["metadata"]["uid"]] = {"role": role, "name": pod["metadata"]["name"],
                "containers": [(value["name"], value.get("containerID"), value["restartCount"]) for value in pod["status"].get("containerStatuses", [])]}
            if role == "fencer":
                fencers.append(pod)
    events = json.loads(c.cluster.kube("get", "events", "-n", scope.namespace, "-o", "json").stdout)["items"]
    for event in events:
        uid = event.get("involvedObject", {}).get("uid")
        if uid not in identities or event.get("reason") != "Unhealthy":
            continue
        message = event.get("message", "").lower()
        category = "Timeout" if "timeout" in message or "deadline" in message else "HTTP503" if "statuscode: 503" in message else "ConnectionRefused" if "connection refused" in message else "Other"
        result["currentPodEvents"].append({"role": identities[uid]["role"], "reason": "Unhealthy", "category": category,
            "count": event.get("count", 1), "lastTime": event.get("lastTimestamp") or event.get("eventTime")})
    tls = ssl.create_default_context(cafile=str(c.private / "journal-ca.crt"))
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect(), urllib.request.HTTPSHandler(context=tls))
    for index, pod in enumerate(sorted(fencers, key=lambda value: value["metadata"]["uid"])):
        with Forward(c.cluster, scope.namespace, "pod/" + pod["metadata"]["name"], 9443) as forward:
            for path in ("/readyz", "/healthz", "/readyz"):
                started = time.monotonic()
                code, category = None, "TransportFailure"
                try:
                    with opener.open(forward.origin + path, timeout=10) as response:
                        code = response.status
                        raw = response.read(2049)
                        category = "OK" if code == 200 and len(raw) <= 2048 else "UnexpectedResponse"
                except urllib.error.HTTPError as error:
                    code = error.code
                    raw = error.read(2049)
                    category = "HTTPFailure"
                except Exception:
                    pass
                result["fencerHTTPSamples"].append({"podIndex": index, "path": path, "http": code,
                    "seconds": round(time.monotonic() - started, 3), "result": category})
    for uid, expected in identities.items():
        pod = json.loads(c.cluster.kube("get", "pod", expected["name"], "-n", scope.namespace, "-o", "json").stdout)
        require(pod["metadata"]["uid"] == uid and [(value["name"], value.get("containerID"), value["restartCount"]) for value in pod["status"].get("containerStatuses", [])] == expected["containers"], "Probe Pod process changed during observations")
    result["podUIDsAndContainerIDsStableDuringSamples"] = True
    result["cpuThrottlingMetricsCollected"] = False
    stamp = str(time.time_ns())
    write_private(c.private / ("probe-observer-identities-" + stamp + ".json"), canonical(identities))
    write_private(c.private / ("probe-observer-safe-" + stamp + ".json"), canonical(result))
    return result
