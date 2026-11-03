// Independent Node WebCrypto checks. Synthetic public keys and canary data only.
const fs = require('node:fs');
const path = require('node:path');
const { webcrypto, createHash } = require('node:crypto');
const { subtle } = webcrypto;
const reader = require('./restricted_reader.cjs');
const vector = JSON.parse(fs.readFileSync(path.join(__dirname, 'public-reader-wrap-vector.json'), 'utf8'));
const utf8 = value => Buffer.from(value, 'utf8');
const unb64 = value => Buffer.from(value, 'base64url');
const b64 = value => Buffer.from(value).toString('base64url');
const hash = value => createHash('sha256').update(value).digest();
const domain = name => Buffer.concat([utf8('sekvyr-e2e2/' + name + '/v1'), Buffer.from([0])]);
function canonical(value) {
  function ordered(item) {
    if (Array.isArray(item)) return item.map(ordered);
    if (item && typeof item === 'object') {
      const keys = Object.keys(item).sort();
      if (keys.some(key => /[^\x00-\x7f]/u.test(key))) throw Error('non-ASCII property');
      return Object.fromEntries(keys.map(key => [key, ordered(item[key])]));
    }
    if (typeof item === 'number' && (!Number.isInteger(item) || item < 0 || item > 1024)) throw Error('number profile');
    if (typeof item === 'string' && !item.isWellFormed()) throw Error('surrogate');
    return item;
  }
  return utf8(JSON.stringify(ordered(value)));
}
function check(value, reason) { if (!value) throw Error(reason); }
async function hmacSHA256(key, input) {
  const imported = await subtle.importKey('raw', key, {name:'HMAC', hash:'SHA-256'}, false, ['sign']);
  return Buffer.from(await subtle.sign('HMAC', imported, input));
}
// RFC 5869 extract + one expansion block, L=32. No info truncation or wire change.
// Node 24 built-in HKDF has a 1024-byte info limit; HMAC itself does not.
async function hkdfSHA256_32(ikm, salt, info) {
  const prk = await hmacSHA256(salt.length ? salt : Buffer.alloc(32), ikm);
  return hmacSHA256(prk, Buffer.concat([info, Buffer.from([1])]));
}
(async () => {
  // RFC 5869 Appendix A.1: official PRK and first 32 bytes of the 42-byte OKM.
  const rfcIKM = Buffer.alloc(22, 0x0b);
  const rfcSalt = Buffer.from('000102030405060708090a0b0c', 'hex');
  const rfcInfo = Buffer.from('f0f1f2f3f4f5f6f7f8f9', 'hex');
  check((await hmacSHA256(rfcSalt, rfcIKM)).toString('hex') === '077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5', 'RFC 5869 PRK');
  check((await hkdfSHA256_32(rfcIKM, rfcSalt, rfcInfo)).toString('hex') === '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf', 'RFC 5869 OKM first block');
  const rfcImported = await subtle.importKey('raw', rfcIKM, 'HKDF', false, ['deriveBits']);
  for (const info of [Buffer.alloc(0), rfcInfo, Buffer.alloc(1024, 0xa5)]) {
    const builtin = await subtle.deriveBits({name:'HKDF', hash:'SHA-256', salt:rfcSalt, info}, rfcImported, 256);
    check(Buffer.from(builtin).equals(await hkdfSHA256_32(rfcIKM, rfcSalt, info)), 'HKDF built-in/HMAC parity');
  }
  const wrapper = vector.wrapper;
  const body = wrapper.body;
  const context = body.context;
  check(canonical(body).equals(unb64(vector.canonical_wrapper_body_base64url)), 'canonical body differs');
  check(canonical(vector.unicode_case).equals(unb64(vector.unicode_canonical_base64url)), 'Unicode JCS bytes differ');
  const publisher = await subtle.importKey('raw', unb64(vector.publisher_public_key), 'Ed25519', false, ['verify']);
  const signedMessage = Buffer.concat([domain('reader-wrap-sign'), canonical(body)]);
  check(await subtle.verify('Ed25519', publisher, unb64(wrapper.signature), signedMessage), 'signature invalid');
  const nodePublic = unb64(vector.node_public_key);
  check(context.recipient_fingerprint === 'p256-sha256:' + hash(nodePublic).toString('hex'), 'recipient fingerprint');
  check(context.publisher_key_id === 'ed25519-sha256:' + hash(unb64(vector.publisher_public_key)).toString('hex'), 'publisher fingerprint');
  const jwk = {kty:'EC', crv:'P-256', x:b64(nodePublic.subarray(1,33)), y:b64(nodePublic.subarray(33)), d:vector.public_test_node_scalar, ext:true};
  const nodePrivate = await subtle.importKey('jwk', jwk, {name:'ECDH', namedCurve:'P-256'}, false, ['deriveBits']);
  const peer = await subtle.importKey('raw', unb64(body.ephemeral_public), {name:'ECDH', namedCurve:'P-256'}, false, []);
  const shared = await subtle.deriveBits({name:'ECDH', public:peer}, nodePrivate, 256);
  check(Buffer.from(shared).equals(unb64(vector.public_test_ecdh_shared_base64url)), 'ECDH bytes differ');
  const hkdf = await subtle.importKey('raw', shared, 'HKDF', false, ['deriveBits']);
  const wrapKey = await subtle.deriveBits({name:'HKDF', hash:'SHA-256', salt:unb64(body.salt), info:Buffer.concat([domain('reader-wrap-key'), canonical(context)])}, hkdf, 256);
  check(Buffer.from(wrapKey).equals(unb64(vector.public_test_wrap_key_base64url)), 'HKDF bytes differ');
  check(Buffer.from(wrapKey).equals(await hkdfSHA256_32(shared, unb64(body.salt), Buffer.concat([domain('reader-wrap-key'), canonical(context)]))), 'wrapper built-in/HMAC HKDF parity');
  const aes = await subtle.importKey('raw', wrapKey, 'AES-GCM', false, ['decrypt']);
  const decrypted = await subtle.decrypt({name:'AES-GCM', iv:unb64(body.nonce), tagLength:128, additionalData:Buffer.concat([domain('reader-wrap-aad'), canonical(context)])}, aes, unb64(body.ciphertext));
  check(Buffer.from(decrypted).equals(unb64(vector.canonical_wrapper_payload_base64url)), 'payload bytes differ');
  const payload = JSON.parse(Buffer.from(decrypted).toString('utf8'));
  check(payload.format === 'sekvyr-e2e2-read-key-v1', 'payload format');
  check(canonical(payload.context).equals(canonical(context)), 'payload context');
  check(payload.read_key === vector.public_test_view_read_key, 'view read key');
  const changedBody = structuredClone(body);
  changedBody.context.view_id = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
  check(!(await subtle.verify('Ed25519', publisher, unb64(wrapper.signature), Buffer.concat([domain('reader-wrap-sign'), canonical(changedBody)]))), 'context substitution accepted');
  check(!(await subtle.verify('Ed25519', publisher, unb64(wrapper.signature), Buffer.concat([domain('publish'), canonical(body)]))), 'wrong signature domain accepted');
  let rejected = false;
  try {
    const broken = unb64(body.ciphertext); broken[0] ^= 1;
    await subtle.decrypt({name:'AES-GCM', iv:unb64(body.nonce), tagLength:128, additionalData:Buffer.concat([domain('reader-wrap-aad'), canonical(context)])}, aes, broken);
  } catch { rejected = true; }
  check(rejected, 'ciphertext substitution accepted');
  const corpus = JSON.parse(fs.readFileSync(path.join(__dirname, 'public-snapshot-corpus.json'), 'utf8'));
  const snapshotPublisher = await subtle.importKey('raw', unb64(corpus.publisher_public_key), 'Ed25519', false, ['verify']);
  const readKey = unb64(corpus.public_test_view_read_key);
  const expected = {scope:reader.scope(corpus.cases[0].envelope.body.header), publisher:unb64(corpus.publisher_public_key),
    publisherID:'ed25519-sha256:' + hash(unb64(corpus.publisher_public_key)).toString('hex'),
    readKeyEpoch:'1', policyEpoch:'1', recipientFingerprint:context.recipient_fingerprint};
  let largestSnapshotInfoBytes = 0;
  let acceptedSnapshots=0, rejectedSnapshots=0;
  for (const item of corpus.cases) {
    const envelope = item.envelope;
    check(await subtle.verify('Ed25519', snapshotPublisher, unb64(envelope.signature), Buffer.concat([domain('publish'), unb64(item.canonical_signed_body_base64url)])), 'corpus signature: ' + item.name);
    let accepted=false;
    try { await reader.snapshot(Buffer.from(JSON.stringify(envelope)),expected,readKey); accepted=true; } catch {}
    check(accepted===item.valid, 'full snapshot acceptance: ' + item.name);
    if (accepted) acceptedSnapshots++; else rejectedSnapshots++;
    if (!item.valid) continue;
    const headerBytes = canonical(envelope.body.header);
    check(canonical(envelope.body).equals(unb64(item.canonical_signed_body_base64url)), 'corpus body canonical: ' + item.name);
    check(hash(Buffer.concat([domain('envelope-hash'), canonical(envelope)])).toString('hex') === item.envelope_hash, 'corpus hash: ' + item.name);
    const info = Buffer.concat([domain('snapshot-key'), headerBytes]);
    largestSnapshotInfoBytes = Math.max(largestSnapshotInfoBytes, info.length);
    const keyBytes = await hkdfSHA256_32(readKey, unb64(envelope.body.header.snapshot_salt), info);
    const key = await subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['decrypt']);
    let bytes;
    try {
      bytes = await subtle.decrypt({name:'AES-GCM', iv:unb64(envelope.body.nonce), tagLength:128, additionalData:Buffer.concat([domain('snapshot-aad'), headerBytes])}, key, unb64(envelope.body.ciphertext));
    } catch (error) {
      throw Error('corpus decrypt ' + item.name + ': ' + error.message);
    }
    check(Buffer.from(bytes).equals(canonical(item.expected_plaintext)), 'corpus plaintext bytes: ' + item.name);
  }
  const wrapCorpus = JSON.parse(fs.readFileSync(path.join(__dirname, 'public-reader-wrap-corpus.json'), 'utf8'));
  let acceptedWraps=0, rejectedWraps=0;
  for (const item of wrapCorpus.cases) {
    check(await subtle.verify('Ed25519', publisher, unb64(item.wrapper.signature), Buffer.concat([domain('reader-wrap-sign'), unb64(item.canonical_signed_body_base64url)])), 'wrap corpus signature: ' + item.name);
    let accepted=false;
    try { const key=await reader.wrapper(Buffer.from(JSON.stringify(item.wrapper)),expected,nodePrivate); check(key.equals(readKey),'read key'); accepted=true; } catch {}
    check(accepted===item.valid, 'full wrapper acceptance: ' + item.name);
    if (accepted) acceptedWraps++; else rejectedWraps++;
  }
  for (const raw of [Buffer.from('{"a":1,"\\u0061":2}'),Buffer.from('{"a":"\\ud800"}'),Buffer.from('{"a":1.0}'),
    Buffer.from('{"a":1e0}'),Buffer.from('{"a":-0}'),Buffer.from([239,187,191,123,125]),Buffer.from([123,34,97,34,58,34,255,34,125]),
    Buffer.from('{"a":9007199254740992}'),Buffer.from('['.repeat(17)+'0'+']'.repeat(17))]) {
    let rejected=false; try { reader.strict(raw,4096); } catch { rejected=true; } check(rejected,'strict raw parser negative');
  }
  check(largestSnapshotInfoBytes > 1024, 'maximum-parent long HKDF info coverage missing');
  console.log(JSON.stringify(await require('./check_authority.cjs').run()));
  console.log(JSON.stringify({scope:'public Python-to-Node WebCrypto reader wrapper and snapshots', readerWrapChecks:15, signedSnapshotCases:corpus.cases.length, signedWrapCases:wrapCorpus.cases.length,
    acceptedSnapshots,rejectedSnapshots,acceptedWraps,rejectedWraps,fullSemanticAcceptance:'passed',hkdfRFC5869:'passed', builtinHKDFParity:'passed at info<=1024', largestSnapshotInfoBytes, result:'passed'}));
})().catch(error => { console.error(error.stack || error.message); process.exitCode = 1; });
