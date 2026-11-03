// PUBLIC independent WebCrypto authority proof checks. No runtime trust loading.
const fs=require('node:fs'), path=require('node:path');
const r=require('./restricted_reader.cjs');
const {exact,check,counter,unb64,canonical,equal,scope,scopeFields,uuid,hashPattern,zero,sha}=r;
const objectFields=['api_version','kind','namespace','name','uid'];
const authorityFields=['revision','admin_key','publisher_policy_epoch','publisher_keys','read_key_epoch','witness_epoch','witness_key','fencer_epoch','fencer_keys'];
function hash(value,allowZero=false) { check(typeof value==='string' && hashPattern.test(value) && (allowZero || value!==zero)); }
function cursor(value) { exact(value,['journal_sequence','record_hash']); counter(value.journal_sequence,true); hash(value.record_hash); }
function key(value) {
  exact(value,['key_id','public_key']);
  const bytes=unb64(value.public_key,32);
  check(!bytes.equals(Buffer.alloc(32)) && !bytes.equals(Buffer.concat([Buffer.from([1]),Buffer.alloc(31)]))
    && value.key_id==='ed25519-sha256:'+sha(bytes));
  // Prime-subgroup trust validation belongs to the production Go authority;
  // all independent pins here are public keys generated from public test seeds.
  return value.key_id;
}
function authority(value) {
  exact(value,authorityFields);
  for (const field of ['revision','publisher_policy_epoch','read_key_epoch','witness_epoch','fencer_epoch']) counter(value[field]);
  const ids=[key(value.admin_key),key(value.witness_key)];
  for (const field of ['publisher_keys','fencer_keys']) {
    check(Array.isArray(value[field]) && value[field].length>=1 && value[field].length<=16);
    let previous='';
    for (const item of value[field]) { const id=key(item); check(id>previous); previous=id; ids.push(id); }
  }
  check(new Set(ids).size===ids.length);
}
function dns(value,namespace=false) {
  return typeof value==='string' && value.length>=1 && value.length<=(namespace?63:253)
    && (namespace?/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/:/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/).test(value);
}
function enrollments(values) {
  check(values!==null && typeof values==='object' && !Array.isArray(values) && Object.keys(values).length<=64);
  for (const [id,e] of Object.entries(values)) {
    exact(e,['installation_id','bootstrap_generation','namespace','namespace_uid','operator_service_account','operator_service_account_uid',
      'fencer_service_account','fencer_service_account_uid','lease','node_fingerprint','identity_key_secret_uid','trust_bundle_secret_uid','allowed_objects']);
    check(id===e.installation_id && Number.isSafeInteger(e.bootstrap_generation) && e.bootstrap_generation>=1 && dns(e.namespace,true));
    for (const field of ['installation_id','namespace_uid','operator_service_account_uid','fencer_service_account_uid','identity_key_secret_uid','trust_bundle_secret_uid']) check(typeof e[field]==='string' && uuid.test(e[field]));
    check(dns(e.operator_service_account) && dns(e.fencer_service_account) && e.operator_service_account!==e.fencer_service_account
      && e.operator_service_account_uid!==e.fencer_service_account_uid && e.identity_key_secret_uid!==e.trust_bundle_secret_uid
      && /^p256-sha256:[0-9a-f]{64}$/.test(e.node_fingerprint));
    exact(e.lease,objectFields);
    check(e.lease.api_version==='coordination.k8s.io/v1' && e.lease.kind==='Lease' && e.lease.namespace===e.namespace && dns(e.lease.name) && uuid.test(e.lease.uid));
    check(Array.isArray(e.allowed_objects) && e.allowed_objects.length>=1 && e.allowed_objects.length<=64);
    let previous='';
    for (const obj of e.allowed_objects) {
      exact(obj,objectFields);
      const order=[obj.api_version,obj.kind,obj.namespace,obj.name].join('\0');
      check(order>previous && obj.namespace===e.namespace && dns(obj.name) && typeof obj.uid==='string' && uuid.test(obj.uid)
        && obj.uid!==e.identity_key_secret_uid && obj.uid!==e.trust_bundle_secret_uid
        && ((obj.api_version==='apps/v1' && obj.kind==='Deployment') || (obj.api_version==='v1' && obj.kind==='Secret')));
      previous=order;
    }
  }
}
async function verify(raw,expected) {
  const proof=exact(r.strict(raw,(1<<20)+(64<<10)),['body','key_id','signature']);
  const body=exact(proof.body,['format','state','request_nonce','floor']);
  check(body.format==='sekvyr-authority-proof-v2' && body.request_nonce===expected.request_nonce && equal(body.floor,expected.floor));
  unb64(body.request_nonce,32); cursor(body.floor);
  const state=exact(body.state,['scope','genesis_hash','cursor','snapshot','authority','authority_digest','enrollments']);
  check(equal(exact(state.scope,scopeFields),expected.scope) && equal(scope(state.scope),expected.scope) && state.genesis_hash===expected.genesis_hash);
  cursor(state.cursor);
  const seq=counter(state.cursor.journal_sequence,true), floor=counter(expected.floor.journal_sequence,true);
  check(seq>=floor && (seq!==floor || state.cursor.record_hash===expected.floor.record_hash));
  authority(state.authority); enrollments(state.enrollments);
  check(equal(state.authority.witness_key,expected.pinned_witness) && state.authority.witness_epoch===expected.witness_epoch && proof.key_id===expected.pinned_witness.key_id);
  const digest={scope:state.scope,genesis_hash:state.genesis_hash,authority:state.authority,enrollments:state.enrollments};
  hash(state.authority_digest);
  check(state.authority_digest===sha(Buffer.concat([Buffer.from('sekvyr-e2e2/authority-state-hash/v1\0'),canonical(digest)])));
  const snapshot=exact(state.snapshot,['sequence','envelope_hash','read_key_epoch','publisher_policy_epoch']);
  const sequence=counter(snapshot.sequence,true); hash(snapshot.envelope_hash,true);
  if (sequence===0n) check(snapshot.envelope_hash===zero && snapshot.read_key_epoch==='0' && snapshot.publisher_policy_epoch==='0');
  else check(snapshot.envelope_hash!==zero && snapshot.read_key_epoch===state.authority.read_key_epoch && snapshot.publisher_policy_epoch===state.authority.publisher_policy_epoch);
  await r.signature(unb64(expected.pinned_witness.public_key,32),Buffer.concat([Buffer.from('sekvyr-e2e2/authority-proof/v2\0'),canonical(body)]),proof.signature);
  return state;
}
async function run() {
  const corpus=JSON.parse(fs.readFileSync(path.join(__dirname,'public-authority-proof-corpus.json'),'utf8'));
  check(corpus.format==='sekvyr-stage7-PUBLIC-authority-corpus-v1');
  let accepted=0,rejected=0;
  for (const item of corpus.cases) {
    const raw=item.raw_base64url?unb64(item.raw_base64url):Buffer.from(JSON.stringify(item.proof));
    let valid=false;
    try { await verify(raw,corpus); valid=true; } catch {}
    check(valid===item.go_valid);
    if (valid) accepted++; else rejected++;
  }
  return {scope:'PUBLIC WebCrypto authority-proof-v2',cases:corpus.cases.length,accepted,rejected,result:'passed'};
}
module.exports={verify,run};
if (require.main===module) run().then(value=>console.log(JSON.stringify(value))).catch(()=>{console.error('PUBLIC authority reference failed');process.exitCode=1;});
