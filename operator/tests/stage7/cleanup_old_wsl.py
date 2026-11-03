"""Remove only the reviewed old WSL trial after real Helm uninstalls."""

import json
import re
from urllib.parse import quote

from app_modes import require, wait
from fixture import canonical, write_private


def cluster_cleanup(c):
    cluster, task = c.cluster, c.task
    namespaces = cluster.namespace_pins()
    pins = [json.loads(p.read_bytes()) for p in cluster.pins.glob('*.json')]
    require(all(not p.is_symlink() for p in cluster.pins.glob('*.json')), 'Cleanup pin symlink denied')
    claim_pins = {(p['namespace'], p['name']): p['uid'] for p in pins if p['kind']=='PersistentVolumeClaim'}
    require(len(claim_pins)==3 and all(ns in namespaces for ns,_ in claim_pins), 'Exact three trial PVC pins required')
    volumes=[]
    for value in json.loads(cluster.kube('get','pv','-o','json').stdout)['items']:
        ref=value.get('spec',{}).get('claimRef',{})
        if ref.get('namespace') in namespaces:
            require(claim_pins.get((ref['namespace'],ref['name']))==ref.get('uid'), 'Trial PV claim identity changed')
            volumes.append({'name':value['metadata']['name'],'uid':value['metadata']['uid']})
    require(len(volumes)==3, 'Three exact owned bound PVs required')
    cluster_pins=cluster.cluster_creation_pins()
    write_private(task/'old-wsl-review-identities.json',canonical({'namespaces':namespaces,'volumes':volumes,
        'clusterResources':cluster_pins,'node':json.loads((c.private/'node-pin.json').read_bytes()),
        'dockerBaseline':json.loads((c.private/'docker-baseline.json').read_bytes())}))
    cluster.cleanup_cluster_resources('before-namespaces',execute=True)
    deleted=0
    for pin in [p for p in pins if p['kind']=='Deployment']:
        require(pin['namespace'] in namespaces,'Cleanup Deployment namespace denied')
        raw=cluster.kube('get','Deployment',pin['name'],'-n',pin['namespace'],'--ignore-not-found','-o','json').stdout.strip()
        if not raw:continue
        value=json.loads(raw)
        require(value['metadata']['uid']==pin['uid'] and not value['metadata'].get('deletionTimestamp'),'Cleanup Deployment replaced')
        body={'apiVersion':'v1','kind':'DeleteOptions','preconditions':{'uid':pin['uid'],'resourceVersion':value['metadata']['resourceVersion']},'propagationPolicy':'Foreground'}
        cluster.kube('delete','--raw','/apis/apps/v1/namespaces/'+quote(pin['namespace'],safe='')+'/deployments/'+quote(pin['name'],safe=''),'-f','-',data=json.dumps(body))
        deleted+=1
    def no_consumers():
        return all(not json.loads(cluster.kube('get','pods','-n',ns,'-o','json').stdout)['items'] for ns in namespaces)
    wait(no_consumers,timeout=180)
    cluster.cleanup_namespaces(execute=True,acknowledge_trial_storage_destruction=True)
    wait(lambda:all(not cluster.kube('get','namespace',ns,'--ignore-not-found','-o','name').stdout.strip() for ns in namespaces),timeout=180)
    def no_volumes():
        for pin in volumes:
            raw=cluster.kube('get','pv',pin['name'],'--ignore-not-found','-o','json').stdout.strip()
            if raw:
                require(json.loads(raw)['metadata']['uid']==pin['uid'],'PV name reused during cleanup')
                return False
        return True
    wait(no_volumes,timeout=180)
    cluster.cleanup_cluster_resources('after-namespaces',execute=True)
    for pin in cluster_pins:
        require(not cluster.kube('get',pin['kind'],pin['name'],'--ignore-not-found','-o','name').stdout.strip(),'Cluster resource remains')
    result={'production':False,'ownNamespacesAbsent':len(namespaces),'ownPVsAbsent':len(volumes),
        'ownClusterResourcesAbsent':len(cluster_pins),'uidRVGuardedDeploymentsRemovedBeforeExternalMaterial':deleted,
        'allConsumersGoneBeforeNamespaceDeletion':True,'trialPVCDestructionAcknowledged':True}
    write_private(task/'old-wsl-cluster-cleanup.json',canonical(result))
    return result


def docker_cleanup(task):
    from prepare import CLUSTER, NODE, baseline, docker, digest
    require((task/'old-wsl-cluster-cleanup.json').is_file(),'Completed cluster cleanup required')
    private=task/'private'
    pin=json.loads((private/'node-pin.json').read_bytes())
    before=json.loads((private/'docker-baseline.json').read_bytes())
    current=json.loads(docker('inspect',pin['id']))
    require(len(current)==1 and current[0]['Id']==pin['id'] and current[0]['Config']['Image']==NODE
        and pin['image']==NODE and current[0]['Config']['Labels'].get('io.x-k8s.kind.cluster')==CLUSTER,
        'Docker cleanup creator identity changed')
    actual_volumes=[v['Name'] for v in current[0].get('Mounts',[]) if v.get('Type')=='volume']
    require(set(actual_volumes)==set(pin['volumes']) and all(re.fullmatch(r'[0-9a-f]{64}',v)
        and v not in before['volumes'] for v in actual_volumes),'Only creation-pinned anonymous volumes may be removed')
    for cid in docker('ps','-a','--no-trunc','--format={{.ID}}').split():
        if cid==pin['id']:continue
        obj=json.loads(docker('inspect',cid))[0]
        require(not any(v.get('Type')=='volume' and v.get('Name') in actual_volumes for v in obj.get('Mounts',[])),
            'Owned anonymous volume is now shared')
    docker('rm','--force',pin['id'])
    for name in actual_volumes:
        # Recheck no other consumer after node deletion; no name-only adoption.
        require(not docker('ps','-a','--filter=volume='+name,'--format={{.ID}}').strip(),'Volume gained a consumer')
        docker('volume','rm',name)
    after=baseline()
    require(after['containers']==before['containers'] and after['volumes']==before['volumes'],
        'Foreign Docker static configuration or volume inventory changed')
    require(after['kindNetworkID']==before['kindNetworkID'] and after['kindNetworkHash']==before['kindNetworkHash'],
        'Original empty kind network identity or full hash changed')
    result={'production':False,'creationPinnedNodeAbsent':True,'ownUnsharedAnonymousVolumesRemoved':len(actual_volumes),
        'preexistingContainers':len(before['containers']),'preexistingVolumes':len(before['volumes']),
        'foreignContainerStaticConfigurationUnchanged':True,'foreignVolumesUnchanged':True,
        'originalKindNetworkIDAndFullHashUnchangedAfterOwnAttachmentRemoved':True,'globalConfigurationChanged':False}
    write_private(task/'old-wsl-docker-cleanup.json',canonical(result))
    return result
