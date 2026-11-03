"""Real namespace/role reachability checks; no upstream credential is mounted."""

import json
import re
import time

from manifests import LABEL, object_resource


def conformance(cluster, python_image, node_name="", label=""):
    if label and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,23}", label) is None:
        raise ValueError("Invalid bounded network proof label")
    namespaces = cluster.fixture["namespaces"]
    gateway = "journal." + namespaces["gateway"] + ".svc.cluster.local"
    upstream = "s3." + namespaces["storage"] + ".svc.cluster.local"
    # A positive connection prevents DNS/startup failures from masquerading as
    # effective denial. Both target names are private fixture inputs, not URLs.
    code = """import json,socket,sys
def connected(host,port):
 try:
  with socket.create_connection((host,port),timeout=3):return True
 except OSError:return False
positive=connected(sys.argv[1],8443)
blocked=not connected(sys.argv[2],8333)
print(json.dumps({'gatewayReachable':positive,'directS3Blocked':blocked}))
sys.exit(0 if positive and blocked else 1)
"""
    checked = []
    for domain, role in (("apps", "operator"), ("apps", "fencer"), ("witness", "witness")):
        name, namespace = "network-proof-" + role + ("-" + label if label else ""), namespaces[domain]
        pod = {"restartPolicy": "Never", "automountServiceAccountToken": False, "enableServiceLinks": False,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65532, "runAsGroup": 65532,
                "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [{"name": "probe", "image": python_image, "imagePullPolicy": "Never",
                "command": ["python3", "-B", "-c", code, gateway, upstream],
                # These role labels exercise the SAME policy, but the probe
                # must never become a Ready endpoint of the witness Service.
                "readinessProbe": {"tcpSocket": {"port": 65535}, "periodSeconds": 1},
                "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                    "capabilities": {"drop": ["ALL"]}},
                "resources": {"requests": {"cpu": "10m", "memory": "16Mi"},
                    "limits": {"cpu": "200m", "memory": "64Mi"}}}]}
        if node_name:
            pod["nodeName"] = node_name
        resource = object_resource("Pod", name, namespace, pod)
        resource["metadata"]["labels"] = {LABEL: role}
        created = cluster.create(resource)
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            live = json.loads(cluster.kube("get", "pod", name, "-n", namespace, "-o", "json").stdout)
            if live["metadata"]["uid"] != created["metadata"]["uid"]:
                raise RuntimeError("Network proof Pod replaced")
            phase = live.get("status", {}).get("phase")
            if phase == "Failed":
                raise RuntimeError("Runtime network boundary proof failed")
            if phase == "Succeeded":
                raw = cluster.kube("logs", name, "-n", namespace, "-c", "probe").stdout
                proof = json.loads(raw)
                if proof != {"gatewayReachable": True, "directS3Blocked": True}:
                    raise RuntimeError("Runtime network proof returned unexpected evidence")
                checked.append(role)
                break
            time.sleep(0.4)
        else:
            raise RuntimeError("Network proof Pod did not finish")
    return {"actualPodNetworkRolesChecked": checked, "positiveJournalTCP": True,
        "directS3TCPDenied": True, "credentialsMountedInProbe": False, "production": False}


def fencer_bootstrap(cluster, python_image):
    """Diagnose exact runtime TLS/SA mounts without signing or writing anything.

    No signing Secret is mounted and every HTTP operation is a read. Output is
    only status codes/UID comparisons, never fetched Secret data or tokens.
    """
    import copy
    ns = cluster.fixture["namespaces"]["apps"]
    deployment = json.loads(cluster.kube("get", "deployment", "stage6-fencer", "-n", ns, "-o", "json").stdout)
    pins = [json.loads(p.read_text()) for p in cluster.pins.glob("*.json")]
    if not any(p["kind"] == "Deployment" and p["namespace"] == ns and p["name"] == "stage6-fencer"
               and p["uid"] == deployment["metadata"]["uid"] for p in pins):
        raise RuntimeError("Diagnostic fencer Deployment is not owned")
    original = deployment["spec"]["template"]["spec"]
    selected = {"configuration", "journal-config", "gateway-ca", "gateway-client", "kube-api"}
    container = original["containers"][0]
    code = """import base64,json,os,ssl,urllib.request,urllib.error
from pathlib import Path
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*args):return None
cfg=json.loads(Path('/etc/sekvyr/fencer/config.json').read_text())
j=json.loads(Path('/etc/sekvyr/journal/client.json').read_text())
def request(context,url,headers):
 opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect(),urllib.request.HTTPSHandler(context=context))
 try:r=opener.open(urllib.request.Request(url,headers=headers),timeout=10)
 except urllib.error.HTTPError as e:r=e
 except Exception as e:
  result={'status':0,'transportError':True,'exceptionType':type(e).__name__}
  reason=getattr(e,'reason',None)
  if reason is not None:result['reasonType']=type(reason).__name__
  if isinstance(getattr(reason,'errno',None),int):result['errno']=reason.errno
  if isinstance(getattr(reason,'verify_code',None),int):result['certificateVerifyCode']=reason.verify_code
  return result
 with r:
  raw=r.read((16<<20)+1)
  result={'status':r.status,'bounded':len(raw)<=16<<20}
  if r.status!=200:
   try:reason=json.loads(raw).get('reason','')
   except Exception:reason=''
   if reason.isalpha() and len(reason)<80:result['reason']=reason
  return result
ctx=ssl.create_default_context(cafile=j['ca_file']);ctx.load_cert_chain(j['client_cert_file'],j['client_key_file'])
proof={'journal':request(ctx,j['origin']+'/v1/storage/logs/'+cfg['log_id']+'/journal',{'X-Sekvyr-Journal-Nonce':base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip('=')})}
root=Path('/var/run/secrets/kubernetes.io/serviceaccount')
ctx=ssl.create_default_context(cafile=str(root/'ca.crt'));token=(root/'token').read_text()
origin='https://'+os.environ['KUBERNETES_SERVICE_HOST']+':'+os.environ['KUBERNETES_SERVICE_PORT_HTTPS']
proof['api']=[request(ctx,origin+'/api/v1/namespaces/'+cfg['namespace']+'/'+resource,{'Authorization':'Bearer '+token}) for resource in ['serviceaccounts/'+cfg['fencer_service_account']]+['secrets/'+p['name'] for p in cfg['material_pins']]]
print(json.dumps(proof))
"""
    name = "fencer-bootstrap-proof-v3"
    pod = object_resource("Pod", name, ns, {
        "serviceAccountName": original["serviceAccountName"], "automountServiceAccountToken": False,
        "restartPolicy": "Never", "securityContext": copy.deepcopy(original["securityContext"]),
        "volumes": [copy.deepcopy(v) for v in original["volumes"] if v["name"] in selected],
        "containers": [{"name": "probe", "image": python_image, "imagePullPolicy": "Never",
            "command": ["python3", "-B", "-c", code],
            "securityContext": copy.deepcopy(container["securityContext"]),
            "readinessProbe": {"tcpSocket": {"port": 65535}},
            "volumeMounts": [copy.deepcopy(v) for v in container["volumeMounts"] if v["name"] in selected]}]})
    pod["metadata"]["labels"] = {LABEL: "fencer"}
    result = cluster.create(pod)
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        live = json.loads(cluster.kube("get", "pod", name, "-n", ns, "-o", "json").stdout)
        if live["metadata"]["uid"] != result["metadata"]["uid"]:
            raise RuntimeError("Diagnostic Pod replaced")
        if live.get("status", {}).get("phase") in ("Succeeded", "Failed"):
            raw = cluster.kube("logs", name, "-n", ns).stdout
            if live["status"]["phase"] != "Succeeded":
                raise RuntimeError("Fencer read-only diagnostic failed")
            return json.loads(raw)
        time.sleep(.5)
    raise RuntimeError("Fencer diagnostic deadline exceeded")


def api_reachability(cluster, python_image):
    import ipaddress
    ns = cluster.fixture["namespaces"]["apps"]
    service = json.loads(cluster.kube("get", "service", "kubernetes", "-n", "default", "-o", "json").stdout)
    endpoints = json.loads(cluster.kube("get", "endpoints", "kubernetes", "-n", "default", "-o", "json").stdout)
    addresses = [("service", str(ipaddress.ip_address(service["spec"]["clusterIP"])), 443)]
    for subset in endpoints["subsets"]:
        if {port["port"] for port in subset["ports"]} != {6443}:
            raise RuntimeError("Unexpected pinned API endpoint port")
        addresses.extend(("endpoint", str(ipaddress.ip_address(item["ip"])), 6443) for item in subset["addresses"])
    addresses.append(("gateway", "journal." + cluster.fixture["namespaces"]["gateway"] + ".svc.cluster.local", 8443))
    code = """import json,socket,sys
proof=[]
for label,host,port in json.loads(sys.argv[1]):
 try:
  with socket.create_connection((host,port),timeout=3):proof.append({'target':label,'connected':True})
 except Exception as e:proof.append({'target':label,'connected':False,'exceptionType':type(e).__name__})
print(json.dumps(proof))
"""
    name = "fencer-api-reachability"
    pod = object_resource("Pod", name, ns, {"restartPolicy": "Never", "automountServiceAccountToken": False,
        "enableServiceLinks": False, "securityContext": {"runAsNonRoot": True, "runAsUser": 65532,
            "runAsGroup": 65532, "seccompProfile": {"type": "RuntimeDefault"}},
        "containers": [{"name": "probe", "image": python_image, "imagePullPolicy": "Never",
            "command": ["python3", "-B", "-c", code, json.dumps(addresses)],
            "readinessProbe": {"tcpSocket": {"port": 65535}},
            "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                "capabilities": {"drop": ["ALL"]}}}]})
    pod["metadata"]["labels"] = {LABEL: "fencer"}
    created = cluster.create(pod)
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        live = json.loads(cluster.kube("get", "pod", name, "-n", ns, "-o", "json").stdout)
        if live["metadata"]["uid"] != created["metadata"]["uid"]:
            raise RuntimeError("API reachability Pod replaced")
        if live.get("status", {}).get("phase") == "Succeeded":
            return json.loads(cluster.kube("logs", name, "-n", ns).stdout)
        if live.get("status", {}).get("phase") == "Failed":
            raise RuntimeError("API reachability diagnostic failed")
        time.sleep(.5)
    raise RuntimeError("API reachability diagnostic deadline exceeded")
