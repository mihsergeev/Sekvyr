"""Read only the current operator's own projected fencer JWT inside its PID NS.

The JWT stays inside the helper process. Only identity/expiry booleans and
authenticated HTTPS Ready status/reason/timing leave the Pod. No signals.
"""

import hashlib
import ipaddress
import json

from app_modes import require
from fixture import canonical, write_private
from process_control import ProcessControl
from protocol import domain

HELPER_IMAGE = "docker.io/library/sekvyr-backend-stage6@sha256:3e25b4aa6b85e5b1b1b828a6e5ff38f721d824a493f421f95566d4ba2eb5aa59"

PROGRAM = r'''
import base64,http.client,ipaddress,json,os,re,socket,ssl,sys,time,urllib.parse
ALLOWED={'AuthenticationDenied','BarrierConflict','BarriersIncomplete','BootstrapMismatch','BoundPodRequired','Cancelled','CASConflict','EnrollmentMismatch','FenceInvalid','FenceMismatch','FenceNotIncreasing','FencerDenied','FencerUnavailable','GrantChanged','GrantInvalid','GrantUnavailable','IdentityMismatch','IdentityRoleCollision','JournalUnavailable','LeaseExpired','LeaseMismatch','LeaseUnavailable','MaterialReplaced','NamespaceReplaced','ObjectDenied','ObjectInvalid','ObjectMissing','ObjectReplaced','PodReplaced','ProjectedTokenInvalid','ProjectedTokenUnavailable','RequestInvalid','ResponseInvalid','ServiceAccountReplaced','SigningKeyUnavailable'}
def run():
 data=json.loads(sys.stdin.buffer.read(65537))
 expected=data['argv']
 raw=open('/proc/1/cmdline','rb').read(65537)
 assert len(raw)<=65536 and raw.endswith(b'\0') and raw[:-1].split(b'\0')==[v.encode() for v in expected]
 fields=dict(line.split(':',1) for line in open('/proc/1/status').read(16385).splitlines() if ':' in line)
 assert os.geteuid()==65532 and fields['Uid'].split()==['65532']*4
 assert os.readlink('/proc/1/ns/pid')==os.readlink('/proc/self/ns/pid')
 os.kill(1,0)
 paths=[v.split('=',1)[1] for v in expected if v.startswith('--fencer-token-file=')]
 assert paths==['/var/run/secrets/sekvyr-fencer/token']
 token=open('/proc/1/root'+paths[0],'rb').read(16385).strip()
 assert 0<len(token)<=16384 and not any(v in token for v in (b' ',b'\r',b'\n',b'\t'))
 claims=json.loads(base64.urlsafe_b64decode(token.split(b'.')[1]+b'='*(-len(token.split(b'.')[1])%4)))
 k=claims.get('kubernetes.io',{})
 audience=claims.get('aud',[]); audience=[audience] if isinstance(audience,str) else audience
 parsed=urllib.parse.urlsplit(data['origin'])
 assert parsed.scheme=='https' and parsed.hostname in ('stage6-fencer.'+data['namespace']+'.svc','stage6-fencer.'+data['namespace']+'.svc.cluster.local')
 assert parsed.port==9443 and parsed.path in ('','/') and not parsed.query and not parsed.fragment and not parsed.username and not parsed.password
 assert re.fullmatch(r'[0-9a-f-]{36}',data['installationID']) and re.fullmatch(r'[0-9a-f]{64}',data['grantHash'])
 context=ssl.create_default_context(cadata=data['ca'])
 output={'audienceMatches':'sekvyr-fence' in audience,'notExpired':type(claims.get('exp')) is int and claims['exp']>time.time(),
  'subjectMatches':claims.get('sub')=='system:serviceaccount:'+data['namespace']+':sekvyr-operator',
  'podUIDMatches':k.get('pod',{}).get('uid')==data['podUID'],'serviceAccountUIDMatches':k.get('serviceaccount',{}).get('uid')==data['serviceAccountUID'],'ready':[]}
 for index,address in enumerate(data['peers']):
  assert ipaddress.ip_address(address).is_private
  class Connection(http.client.HTTPSConnection):
   def connect(self):
    sock=socket.create_connection((address,9443),timeout=10)
    self.sock=context.wrap_socket(sock,server_hostname=parsed.hostname)
  connection=(http.client.HTTPSConnection(parsed.hostname,9443,context=context,timeout=10)
   if data.get('serviceOnly') is True else Connection(parsed.hostname,9443,context=context,timeout=10))
  began=time.monotonic(); code=None; reason='TransportUnavailable'
  try:
   connection.request('POST','/v1/installations/'+data['installationID']+'/ready',body=json.dumps({'grant_hash':data['grantHash']}),headers={'Content-Type':'application/json','Authorization':'Bearer '+token.decode()})
   response=connection.getresponse(); code=response.status; body=response.read(2049)
   if code==200:reason='OK'
   elif len(body)<=2048:
    candidate=json.loads(body).get('reason','Unclassified')
    reason=candidate if candidate in ALLOWED else 'Unclassified'
  except Exception:pass
  finally:connection.close()
  output['ready'].append({'podIndex':index,'http':code,'reason':reason,'seconds':round(time.monotonic()-began,3)})
 print(json.dumps(output),flush=True)
try:run()
except BaseException:print(json.dumps({'diagnostic':'ProjectedReadyUnavailable'}),flush=True)
'''


def run(c, *, control=None, service_only=False):
    pod, holder = c.app.operator_pod()
    if control is None:
        control = ProcessControl(c.cluster, pod, HELPER_IMAGE)
        control.prepare()
    require(control.uid == pod['metadata']['uid'] and control.image == HELPER_IMAGE and control.created,
        'Projected probe control is not the current prepared helper')
    c.projected_ready_control = control
    write_private(c.private / ('projected-ready-service-handle.json' if service_only else 'projected-ready-handle.json'),
        canonical({'podUID': control.uid, 'containerID': control.container_id, 'helper': control.control_name,
            'provenance': getattr(control, 'probe_provenance', 'CreateResponse')}))
    state = c.current()
    saved_enrollment = json.loads((c.private / "e2e-cases" / "node-rotation" / "enrollment.json").read_bytes())["body"]["enrollment"]
    require(state["authority"] == c.protocol.authority and state["enrollments"][c.protocol.installation_id] == saved_enrollment, "Projected probe canonical context changed")
    grant = state["grants"][c.protocol.installation_id]["body"]
    require(grant["owner_pod_uid"] == pod["metadata"]["uid"] and grant["lease_holder_identity"] == holder and grant["snapshot"] == state["snapshot"], "Projected probe grant is not current")
    digest = hashlib.sha256(domain("sekvyr-e2e2/fence-grant-hash/v1") + canonical(grant)).hexdigest()
    deployment = c.app.get("Deployment", "stage6-fencer")
    labels = ",".join(key + "=" + value for key, value in sorted(deployment["spec"]["selector"]["matchLabels"].items()))
    sets = json.loads(c.cluster.kube("get", "replicasets", "-n", c.app.namespace, "-l", labels, "-o", "json").stdout)["items"]
    require(all(any(ref.get("kind") == "Deployment" and ref.get("uid") == deployment["metadata"]["uid"] for ref in value["metadata"].get("ownerReferences", [])) for value in sets), "Projected probe peer ReplicaSet owner differs")
    owners = {value["metadata"]["uid"] for value in sets}
    peers = json.loads(c.cluster.kube("get", "pods", "-n", c.app.namespace, "-l", labels, "-o", "json").stdout)["items"]
    peers = [value for value in peers if not value["metadata"].get("deletionTimestamp")]
    require(len(peers) == 2 and all(any(ref.get("kind") == "ReplicaSet" and ref.get("uid") in owners for ref in value["metadata"].get("ownerReferences", [])) for value in peers), "Projected probe peer Pod owner differs")
    active = json.loads((c.private / "e2e-cases" / "readiness-upgrade" / "plan.json").read_bytes())["newValues"]
    payload = {"argv": control.expected_argv, "namespace": c.app.namespace, "podUID": pod["metadata"]["uid"],
        "serviceAccountUID": c.app.get("ServiceAccount", "sekvyr-operator")["metadata"]["uid"],
        "installationID": c.protocol.installation_id, "grantHash": digest, "origin": active["ha"]["config"]["fencerOrigin"],
        "ca": c.app.materials["fencer_ca"].decode(), "serviceOnly": service_only,
        "peers": [str(ipaddress.ip_address(value["status"]["podIP"])) for value in peers[:1] if service_only]
            if service_only else [str(ipaddress.ip_address(value["status"]["podIP"])) for value in peers]}
    # Read the exact admin-reviewed origin, never an arbitrary request URL.
    control._owned()
    response = c.cluster.kube("exec", "-i", control.name, "-n", control.namespace, "-c", control.control_name, "--", "python", "-B", "-c", PROGRAM, data=canonical(payload).decode(), check=False)
    require(response.returncode == 0 and len(response.stdout.encode()) <= 8192, "Projected probe execution incomplete")
    result = json.loads(response.stdout)
    require("diagnostic" not in result, "Projected probe identity or transport setup failed")
    control._owned()
    for peer in peers:
        current = json.loads(c.cluster.kube("get", "pod", peer["metadata"]["name"], "-n", c.app.namespace, "-o", "json").stdout)
        require(current["metadata"]["uid"] == peer["metadata"]["uid"], "Projected probe peer was replaced")
    after = c.current()
    require(after['authority'] == state['authority'] and after['snapshot'] == state['snapshot']
        and after['grants'][c.protocol.installation_id] == state['grants'][c.protocol.installation_id],
        'Projected probe canonical context changed during request')
    write_private(c.private / ('projected-ready-service-probe.json' if service_only else 'projected-ready-probe.json'), canonical(result))
    return result
