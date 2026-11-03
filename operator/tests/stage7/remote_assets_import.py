"""Import reviewed public archives only inside a creator-bound remote kind node."""

import hashlib
import json
from pathlib import Path
import re

from app_modes import require
from fixture import canonical, write_private
from remote_kind_capability import Capability

REFERENCES = {
    'operator':'docker.io/library/sekvyr-operator-stage7@sha256:d328c35df0557ace446628172658d463e05eae0afeb2c11d283f090a80b21652',
    'backend':'docker.io/library/sekvyr-backend-stage6@sha256:3e25b4aa6b85e5b1b1b828a6e5ff38f721d824a493f421f95566d4ba2eb5aa59',
    'postgres':'docker.io/library/postgres@sha256:10a5c69a83035ab5239f5620d708520e8b28f5aa1f2b20143e6024532edadfb5',
    'seaweed':'ghcr.io/chrislusf/seaweedfs@sha256:f7a49e3f3972ebed5be2ed4befa4a0c68eb7bdddba6e692d42729ceb545134b8',
    'python':'docker.io/library/python@sha256:cd89c30eda26ee911a4611b18680086e0ea42e6f5f8cbe653d07fa7958c9cec8',
    'agent':'ghcr.io/mihsergeev/sekvyr-agent@sha256:efa4b55850a1e0ea5b31907991dae8fa163bb7218c648dc8d8b609b90d96d884',
}


def rows(owner):
    return [v.split() for v in owner.exec('ctr','-n','k8s.io','images','list').decode().splitlines()[1:] if v.split()]


def exact_alias(owner, values, name, target):
    matches=[v for v in values if v[0]==name]
    require(not matches or len(matches)==1 and matches[0][2]==target,'Containerd alias collides with another image')
    if not matches:
        sources=sorted(v[0] for v in values if v[2]==target)
        require(sources,'Verified imported root has no image reference')
        owner.exec('ctr','-n','k8s.io','images','tag',sources[0],name)


def run(cluster):
    owner=Capability(cluster)
    metadata=owner.root/'receipts/public-assets.json'
    require(metadata.resolve()==metadata and not metadata.is_symlink() and metadata.stat().st_uid==0,'Public asset receipt unsafe')
    manifest=json.loads(metadata.read_bytes())
    require(manifest['format']=='sekvyr-stage7-public-assets-v1' and manifest['rootTask']==str(owner.root),'Public asset receipt root differs')
    directory=owner.task/'private/image-imports';directory.mkdir(mode=0o700)
    for role,reference in REFERENCES.items():
        entry=manifest['archives'][role];path=owner.root/'assets'/(role+'.tar');target=reference.split('@')[1]
        require(entry['path']==str(path) and entry['rootDigest']==target and path.resolve()==path
            and not path.is_symlink() and path.stat().st_uid==0 and path.stat().st_size==entry['archiveBytes']<=256<<20,'Public archive identity differs')
        raw=path.read_bytes()
        require(hashlib.sha256(raw).hexdigest()==entry['archiveSHA256'],'Public archive bytes changed')
        before=rows(owner);names={v[0] for v in before}
        write_private(directory/(role+'-intent.json'),canonical({'reference':reference,'archiveSHA256':entry['archiveSHA256'],'bytes':len(raw)}))
        owner.exec('ctr','-n','k8s.io','images','import','--digests','--platform','linux/amd64','-',data=raw)
        del raw
        content=owner.exec('ctr','-n','k8s.io','content','get',target)
        require('sha256:'+hashlib.sha256(content).hexdigest()==target,'Imported immutable root checksum differs')
        values=rows(owner);exact_alias(owner,values,reference,target)
        allowed={target,entry['linuxAMD64ManifestDigest']}
        for value in values:
            name=value[0]
            if name in names or not re.fullmatch(r'import-[0-9]{4}-[0-9]{2}-[0-9]{2}@sha256:[0-9a-f]{64}',name):continue
            require(name.split('@')[1]==value[2],'Bare import alias target differs')
            if value[2] not in allowed:
                payload=owner.exec('ctr','-n','k8s.io','content','get',value[2])
                require('sha256:'+hashlib.sha256(payload).hexdigest()==value[2],'Archive wrapper checksum differs')
                wrapped=json.loads(payload).get('manifests',[])
                require(len(wrapped)==1 and wrapped[0]['digest'] in allowed,'Archive wrapper references another image')
            exact_alias(owner,rows(owner),'docker.io/library/'+name,value[2])
        matches=[v for v in rows(owner) if v[0]==reference]
        require(len(matches)==1 and matches[0][2]==target,'Canonical CRI image reference differs')
        write_private(directory/(role+'-complete.json'),canonical({'rootAndArchiveSHA256Verified':True,'canonicalCRIReferenceVerified':True,'hostDockerImageLoaded':False}))
        print('OWN_KIND_IMAGE_ACCEPTED',role,flush=True)
    binary=owner.root/'tools/sekvyr-checkpoint-recovery';raw=binary.read_bytes()
    require(hashlib.sha256(raw).hexdigest()=='641c2670ab103579ecb051f50f69fe9597b401b12093b5edf2a2b641422a6cc8','Recovery CLI source differs')
    target=owner.task/'tools/sekvyr-checkpoint-recovery';write_private(target,raw);target.chmod(0o555)
    write_private(owner.task/'private/recovery-binary.json',canonical({'image':REFERENCES['operator'],'sha256':hashlib.sha256(raw).hexdigest()}))
    result={'publicImagesImportedInsideCreationPinnedKind':len(REFERENCES),'hostDockerImageImports':0,'nativeCLI641Verified':True,'production':False}
    write_private(owner.task/'public-images-ready.json',canonical(result))
    return result
