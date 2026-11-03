// Independent test reader. Public vectors only; no browser product or network.
const {webcrypto, createHash} = require('node:crypto');
const {subtle} = webcrypto;
const decoder = new TextDecoder('utf-8', {fatal:true, ignoreBOM:true});
const scopeFields = ['realm_id','project_id','environment_id','view_id','log_id'];
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const hashPattern = /^[0-9a-f]{64}$/;
const zero = '0'.repeat(64);
function check(ok) { if (!ok) throw Error('Public reference rejected input'); }
function domain(name) { return Buffer.from('sekvyr-e2e2/' + name + '/v1\0'); }
function sha(raw) { return createHash('sha256').update(raw).digest('hex'); }
function exact(value, fields) {
  check(value !== null && !Array.isArray(value) && typeof value === 'object');
  check(Object.keys(value).sort().join('\0') === [...fields].sort().join('\0'));
  return value;
}
function unb64(value, size) {
  check(typeof value === 'string' && /^[A-Za-z0-9_-]*$/.test(value));
  const raw = Buffer.from(value, 'base64url');
  check(raw.toString('base64url') === value && (size === undefined || raw.length === size));
  return raw;
}
function counter(value, allowZero=false) {
  check(typeof value === 'string' && /^(0|[1-9][0-9]{0,19})$/.test(value));
  const number = BigInt(value);
  check(number <= 18446744073709551615n && (allowZero || number > 0n));
  return number;
}
function canonical(value) {
  function sorted(v) {
    if (Array.isArray(v)) return v.map(sorted);
    if (v && typeof v === 'object') {
      const keys = Object.keys(v).sort();
      check(keys.every(key => /^[\x20-\x7e]*$/.test(key)));
      return Object.fromEntries(keys.map(key => [key, sorted(v[key])]));
    }
    check(typeof v !== 'number' || (Number.isSafeInteger(v) && v >= 0));
    check(typeof v !== 'string' || v.isWellFormed());
    return v;
  }
  return Buffer.from(JSON.stringify(sorted(value)), 'utf8');
}
function strict(raw, maximum) {
  raw = Buffer.from(raw);
  check(raw.length > 0 && raw.length <= maximum && !raw.subarray(0,3).equals(Buffer.from([239,187,191])));
  const text = decoder.decode(raw);
  let i=0, nodes=0;
  function whitespace() { while (i<text.length && /[ \t\r\n]/.test(text[i])) i++; }
  function string() {
    const start=i++;
    while (i<text.length) {
      if (text[i] === '\\') { i+=2; continue; }
      if (text[i++] === '"') {
        const value=JSON.parse(text.slice(start,i));
        check(value.isWellFormed());
        return value;
      }
    }
    throw Error('Public reference rejected string');
  }
  function value(depth) {
    check(depth<=16 && ++nodes<=16384);
    whitespace();
    if (text[i] === '"') return string();
    if (text[i] === '{') {
      i++; whitespace(); const result=Object.create(null), keys=new Set();
      if (text[i] === '}') { i++; return result; }
      while (true) {
        check(text[i] === '"'); const key=string();
        check(/^[\x20-\x7e]*$/.test(key) && !keys.has(key) && keys.size<64); keys.add(key);
        whitespace(); check(text[i++] === ':'); result[key]=value(depth+1); whitespace();
        if (text[i] === '}') { i++; return result; }
        check(text[i++] === ','); whitespace();
      }
    }
    if (text[i] === '[') {
      i++; whitespace(); const result=[];
      if (text[i] === ']') { i++; return result; }
      while (true) {
        check(result.length<4096); result.push(value(depth+1)); whitespace();
        if (text[i] === ']') { i++; return result; }
        check(text[i++] === ','); whitespace();
      }
    }
    for (const [token, result] of [['true',true],['false',false],['null',null]]) {
      if (text.startsWith(token,i)) { i+=token.length; return result; }
    }
    const match=/^(0|[1-9][0-9]*)/.exec(text.slice(i));
    check(match); i+=match[0].length;
    const number=Number(match[0]); check(Number.isSafeInteger(number)); return number;
  }
  const parsed=value(0); whitespace(); check(i===text.length); return parsed;
}
function scope(value) {
  const result={};
  for (const field of scopeFields) { check(typeof value[field] === 'string' && uuid.test(value[field])); result[field]=value[field]; }
  return result;
}
function equal(a,b) { return canonical(a).equals(canonical(b)); }
function nonzeroHash(value) { return typeof value === 'string' && hashPattern.test(value) && value!==zero; }
function metadata(value) { return typeof value === 'string' && value.isWellFormed() && value.normalize('NFC')===value && !/[\p{Cc}\p{Cf}\p{Cs}]/u.test(value); }
function validPath(value) {
  if (!metadata(value) || !value.startsWith('/') || [...value].length>200 || value.includes('\\')) return false;
  return value==='/' || value.slice(1).split('/').every(part => part && part!=='.' && part!=='..');
}
function header(h, expected) {
  exact(h,[...scopeFields,'protocol','suite','intent','sequence','previous_hash','read_key_epoch','publisher_policy_epoch','publisher_key_id','snapshot_salt','entry_count','action','restored_from','parents']);
  check(h.protocol==='e2e2' && h.suite==='HKDF-SHA256+A256GCM+Ed25519' && h.intent==='publish' && equal(scope(h),expected.scope));
  const sequence=counter(h.sequence); counter(h.read_key_epoch); counter(h.publisher_policy_epoch);
  check(h.read_key_epoch===expected.readKeyEpoch && h.publisher_policy_epoch===expected.policyEpoch && h.publisher_key_id===expected.publisherID);
  if (sequence===1n) check(h.previous_hash===zero && ['initial','migrate'].includes(h.action));
  else check(nonzeroHash(h.previous_hash) && ['update','restore','rotate-read-key'].includes(h.action));
  check(h.action==='restore' ? nonzeroHash(h.restored_from) : h.restored_from===null);
  unb64(h.snapshot_salt,32);
  check(Number.isInteger(h.entry_count) && h.entry_count>=0 && h.entry_count<=1024 && Array.isArray(h.parents) && h.parents.length<=16);
  let previous='';
  for (const parent of h.parents) {
    exact(parent,[...scopeFields,'sequence','envelope_hash']);
    const parentScope=scope(parent), order=scopeFields.map(key=>parent[key]).join('\0');
    check(!equal(parentScope,expected.scope) && order>previous && nonzeroHash(parent.envelope_hash)); counter(parent.sequence); previous=order;
  }
}
async function hkdf(ikm,salt,info) {
  async function hmac(key,raw) { const k=await subtle.importKey('raw',key,{name:'HMAC',hash:'SHA-256'},false,['sign']); return Buffer.from(await subtle.sign('HMAC',k,raw)); }
  const prk=await hmac(salt.length?salt:Buffer.alloc(32),ikm);
  return hmac(prk,Buffer.concat([info,Buffer.from([1])]));
}
async function aesDecrypt(key,nonce,ciphertext,aad) {
  const k=await subtle.importKey('raw',key,'AES-GCM',false,['decrypt']);
  return Buffer.from(await subtle.decrypt({name:'AES-GCM',iv:nonce,tagLength:128,additionalData:aad},k,ciphertext));
}
async function signature(publicKey,raw,sig) {
  const key=await subtle.importKey('raw',publicKey,'Ed25519',false,['verify']);
  check(await subtle.verify('Ed25519',key,unb64(sig,64),raw));
}
async function snapshot(raw,expected,readKey) {
  const envelope=exact(strict(raw,16<<20),['body','signature']);
  const body=exact(envelope.body,['header','nonce','ciphertext']); header(body.header,expected);
  await signature(expected.publisher,Buffer.concat([domain('publish'),canonical(body)]),envelope.signature);
  const ciphertext=unb64(body.ciphertext); check(ciphertext.length>=16 && ciphertext.length<=(8<<20)+16);
  const key=await hkdf(readKey,unb64(body.header.snapshot_salt,32),Buffer.concat([domain('snapshot-key'),canonical(body.header)]));
  const plain=await aesDecrypt(key,unb64(body.nonce,12),ciphertext,Buffer.concat([domain('snapshot-aad'),canonical(body.header)]));
  const values=exact(strict(plain,8<<20),['format','context','entries']);
  check(canonical(values).equals(plain) && values.format==='sekvyr-e2e2-values-v1' && equal(exact(values.context,scopeFields),expected.scope));
  check(Array.isArray(values.entries) && values.entries.length===body.header.entry_count && values.entries.length<=1024);
  let previous=null, budget=8<<20;
  for (const entry of values.entries) {
    exact(entry,['path','name','value']);
    check(validPath(entry.path) && metadata(entry.name) && [...entry.name].length>=1 && [...entry.name].length<=200
      && typeof entry.value==='string' && entry.value.isWellFormed() && [...entry.value].length<=200000);
    for (const field of ['path','name','value']) { budget-=Buffer.byteLength(entry[field]); check(budget>=0); }
    if (previous) { const pathOrder=Buffer.compare(Buffer.from(previous.path),Buffer.from(entry.path)); check(pathOrder<0 || (pathOrder===0 && Buffer.compare(Buffer.from(previous.name),Buffer.from(entry.name))<0)); }
    previous=entry;
  }
  return values;
}
async function wrapper(raw,expected,nodePrivate) {
  const wrap=exact(strict(raw,16<<10),['body','signature']);
  const body=exact(wrap.body,['context','ephemeral_public','salt','nonce','ciphertext']);
  const context=exact(body.context,[...scopeFields,'protocol','read_key_epoch','publisher_policy_epoch','publisher_key_id','recipient_fingerprint']);
  check(context.protocol==='e2e2-reader-key-v1' && equal(scope(context),expected.scope)
    && context.read_key_epoch===expected.readKeyEpoch && context.publisher_policy_epoch===expected.policyEpoch
    && context.publisher_key_id===expected.publisherID && context.recipient_fingerprint===expected.recipientFingerprint);
  counter(context.read_key_epoch); counter(context.publisher_policy_epoch);
  const publicBytes=unb64(body.ephemeral_public,65); check(publicBytes[0]===4);
  const ciphertext=unb64(body.ciphertext); check(ciphertext.length>=16 && ciphertext.length<=2064);
  await signature(expected.publisher,Buffer.concat([domain('reader-wrap-sign'),canonical(body)]),wrap.signature);
  const peer=await subtle.importKey('raw',publicBytes,{name:'ECDH',namedCurve:'P-256'},false,[]);
  const shared=await subtle.deriveBits({name:'ECDH',public:peer},nodePrivate,256);
  const key=await hkdf(Buffer.from(shared),unb64(body.salt,32),Buffer.concat([domain('reader-wrap-key'),canonical(context)]));
  const plain=await aesDecrypt(key,unb64(body.nonce,12),ciphertext,Buffer.concat([domain('reader-wrap-aad'),canonical(context)]));
  const payload=exact(strict(plain,2048),['format','context','read_key']);
  check(canonical(payload).equals(plain) && payload.format==='sekvyr-e2e2-read-key-v1' && equal(payload.context,context));
  return unb64(payload.read_key,32);
}
module.exports={strict,canonical,exact,scope,scopeFields,uuid,hashPattern,zero,counter,unb64,domain,sha,check,equal,signature,snapshot,wrapper};
