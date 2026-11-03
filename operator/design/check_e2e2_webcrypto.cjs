// Cross-language design vectors only; not browser UI or production SDK.
const fs = require('node:fs');
const path = require('node:path');
const { webcrypto, createHash } = require('node:crypto');
const { subtle } = webcrypto;
const vector = JSON.parse(fs.readFileSync(path.join(__dirname, 'e2e2.public-vectors.json'), 'utf8'));
const utf8 = value => Buffer.from(value, 'utf8');
const domain = name => Buffer.concat([utf8('sekvyr-e2e2/' + name + '/v1'), Buffer.from([0])]);
const unb64 = value => Buffer.from(value, 'base64url');
const sha = value => createHash('sha256').update(value).digest();
function canonical(value) {
  function sorted(x) {
    if (Array.isArray(x)) return x.map(sorted);
    if (x && typeof x === 'object') return Object.fromEntries(Object.keys(x).sort().map(k => [k, sorted(x[k])]));
    if (typeof x === 'number' && (!Number.isSafeInteger(x) || x < 0 || x > 1024)) throw Error('profile number');
    return x;
  }
  return utf8(JSON.stringify(sorted(value)));
}
function check(ok, name) { if (!ok) throw Error(name); }
(async () => {
  const e = vector.envelope;
  const body = canonical(e.body);
  check(body.equals(unb64(vector.canonical_body_base64url)), 'canonical body');
  check(canonical(vector.unicode_case).equals(unb64(vector.unicode_canonical_base64url)), 'unicode canonical bytes');
  const pk = await subtle.importKey('raw', unb64(vector.publisher_public_key), 'Ed25519', false, ['verify']);
  check(await subtle.verify('Ed25519', pk, unb64(e.signature), Buffer.concat([domain('publish'), body])), 'Ed25519');
  const expectedHash = sha(Buffer.concat([domain('envelope-hash'), canonical(e)])).toString('hex');
  check(expectedHash === vector.envelope_hash, 'envelope hash');
  const ikm = sha(utf8('sekvyr-e2e2-public-test-vector/view-read'));
  const hk = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const keyBytes = await subtle.deriveBits({name:'HKDF',hash:'SHA-256',
    salt:unb64(e.body.header.snapshot_salt),
    info:Buffer.concat([domain('snapshot-key'), canonical(e.body.header)])}, hk, 256);
  const aes = await subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['decrypt']);
  const plain = await subtle.decrypt({name:'AES-GCM',iv:unb64(e.body.nonce),tagLength:128,
    additionalData:Buffer.concat([domain('snapshot-aad'), canonical(e.body.header)])},
    aes, unb64(e.body.ciphertext));
  check(Buffer.from(plain).equals(canonical(vector.plaintext)), 'HKDF+AES-GCM plaintext');
  const wp = await subtle.importKey('raw', unb64(vector.witness_public_key), 'Ed25519', false, ['verify']);
  check(await subtle.verify('Ed25519', wp, unb64(vector.head_proof.signature),
    Buffer.concat([domain('head'), canonical(vector.head_proof.body)])), 'witness signature');
  check(vector.head_proof.body.request_nonce === vector.challenge_nonce, 'head nonce');
  check(vector.head_proof.body.floor_hash === vector.envelope_hash, 'canonical floor');
  console.log(JSON.stringify({scope:'Node WebCrypto design vectors, not a browser or Go runtime test',checks:8,result:'passed'}));
})().catch(error => { console.error(error.message); process.exitCode = 1; });
