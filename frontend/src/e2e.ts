/* Шифрование в браузере для проектов, значений которых сервер не видит.
 *
 * Здесь живет вся криптография этого режима. Сервер хранит только результат:
 * запечатанные значения и обертки ключа проекта. Раскрыть их он не может, и в
 * этом весь смысл - компрометация распечатанной панели перестает означать
 * доступ к значениям.
 *
 * Устройство:
 *
 *   - ключ проекта - 32 случайных байта, рождается здесь и живет только во
 *     вкладке;
 *   - пароль проекта превращается в ключ-обертку (PBKDF2-SHA256, 600 000
 *     итераций) и запечатывает ключ проекта;
 *   - для машины ключ проекта запечатывается на её публичный ключ (ECDH P-256):
 *     эфемерная пара браузера плюс ключ ноды дают общий секрет, из него HKDF
 *     выводит ключ обертки.
 *
 * Кривая P-256, а не X25519: её умеют все браузеры и стандартная библиотека Go,
 * на которой написан агент. X25519 в WebCrypto появился недавно и есть не
 * везде, а режим, работающий в половине браузеров, хуже отсутствующего.
 *
 * Цена режима названа прямо: забытый пароль проекта - это потеря значений без
 * вариантов. Восстанавливать их некому.
 */

const PREFIX = 'e2e1:'
const NONCE_LEN = 12
const SALT_LEN = 16
/** Известная строка под ключом проекта: по ней проверяется пароль. */
const VERIFIER_TEXT = 'sekvyr-e2e-v1'

/* Буферы держим на обычном ArrayBuffer: WebCrypto не принимает представления
 * над SharedArrayBuffer, и типы это отражают. */
export type Bytes = Uint8Array<ArrayBuffer>

export type ProjectWrap = {
  salt: string
  nonce: string
  wrapped_key: string
  verifier_nonce: string
  verifier: string
  iterations: number
}

function toBase64(raw: ArrayBuffer | Bytes): string {
  const bytes = raw instanceof Uint8Array ? raw : new Uint8Array(raw)
  let text = ''
  bytes.forEach((byte) => {
    text += String.fromCharCode(byte)
  })
  return btoa(text)
}

function fromBase64(text: string): Bytes {
  const binary = atob(text)
  const out = new Uint8Array(new ArrayBuffer(binary.length))
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i)
  return out
}

function random(length: number): Bytes {
  return crypto.getRandomValues(new Uint8Array(new ArrayBuffer(length)))
}

async function aesKey(raw: Bytes): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt'])
}

/** Ключ-обертка из пароля проекта. Медленно намеренно: пароль слабее ключа. */
async function keyFromPassword(
  password: string,
  salt: Bytes,
  iterations: number,
): Promise<CryptoKey> {
  const material = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    'PBKDF2',
    false,
    ['deriveKey'],
  )
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  )
}

/** Новый ключ проекта и все, что панель должна о нем хранить. */
export async function createProjectKey(
  password: string,
  iterations: number,
): Promise<{ key: Bytes; wrap: ProjectWrap }> {
  const key = random(32)
  const salt = random(SALT_LEN)
  const nonce = random(NONCE_LEN)
  const wrapper = await keyFromPassword(password, salt, iterations)
  const wrapped = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, wrapper, key)

  // Маркер: он позволяет проверить пароль, не подбирая ключ на значениях и не
  // выясняя правильность по тому, "получился ли осмысленный текст".
  const verifierNonce = random(NONCE_LEN)
  const verifier = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: verifierNonce },
    await aesKey(key),
    new TextEncoder().encode(VERIFIER_TEXT),
  )

  return {
    key,
    wrap: {
      salt: toBase64(salt),
      nonce: toBase64(nonce),
      wrapped_key: toBase64(wrapped),
      verifier_nonce: toBase64(verifierNonce),
      verifier: toBase64(verifier),
      iterations,
    },
  }
}

/** Достает ключ проекта из обертки. Возвращает null, если пароль не тот. */
export async function unlockProjectKey(
  wrap: ProjectWrap,
  password: string,
): Promise<Bytes | null> {
  try {
    const wrapper = await keyFromPassword(
      password,
      fromBase64(wrap.salt),
      wrap.iterations || 600000,
    )
    const key: Bytes = new Uint8Array(
      await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: fromBase64(wrap.nonce) },
        wrapper,
        fromBase64(wrap.wrapped_key),
      ),
    )
    const checked = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: fromBase64(wrap.verifier_nonce) },
      await aesKey(key),
      fromBase64(wrap.verifier),
    )
    if (new TextDecoder().decode(checked) !== VERIFIER_TEXT) return null
    return key
  } catch {
    // Неверный пароль и испорченная обертка выглядят одинаково - и должны:
    // по разнице ответов подбирают пароль быстрее.
    return null
  }
}

export function isSealed(value: string): boolean {
  return value.startsWith(PREFIX)
}

export async function sealValue(key: Bytes, value: string): Promise<string> {
  const nonce = random(NONCE_LEN)
  const blob: Bytes = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce },
      await aesKey(key),
      new TextEncoder().encode(value),
    ),
  )
  const packed: Bytes = new Uint8Array(new ArrayBuffer(nonce.length + blob.length))
  packed.set(nonce)
  packed.set(blob, nonce.length)
  return PREFIX + toBase64(packed)
}

export async function openValue(key: Bytes, sealed: string): Promise<string> {
  if (!isSealed(sealed)) return sealed
  const packed = fromBase64(sealed.slice(PREFIX.length))
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: packed.slice(0, NONCE_LEN) },
    await aesKey(key),
    packed.slice(NONCE_LEN),
  )
  return new TextDecoder().decode(plain)
}

/** Ключ проекта, запечатанный на публичный ключ машины. */
export async function wrapForMachine(
  key: Bytes,
  machinePublicKey: string,
): Promise<{ ephemeral_public: string; nonce: string; wrapped_key: string }> {
  const theirs = await crypto.subtle.importKey(
    'raw',
    fromBase64(machinePublicKey),
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    [],
  )
  // Эфемерная пара на каждую выдачу: один и тот же общий секрет для двух разных
  // оберток означал бы, что смена ключа проекта ничего не меняет.
  const mine = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, [
    'deriveBits',
  ])
  const shared = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: theirs },
    mine.privateKey,
    256,
  )
  const material = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey'])
  const wrapper = await crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(new ArrayBuffer(0)),
      info: new TextEncoder().encode('sekvyr-e2e-machine-v1'),
    },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt'],
  )
  const nonce = random(NONCE_LEN)
  const wrapped = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, wrapper, key)
  const exported = await crypto.subtle.exportKey('raw', mine.publicKey)
  return {
    ephemeral_public: toBase64(exported),
    nonce: toBase64(nonce),
    wrapped_key: toBase64(wrapped),
  }
}

/** Ключ проекта живет только в памяти вкладки: ни localStorage, ни куки. */
const unlocked = new Map<number, Bytes>()

export function rememberKey(projectId: number, key: Bytes): void {
  unlocked.set(projectId, key)
}

export function forgetKey(projectId: number): void {
  unlocked.delete(projectId)
}

export function keyFor(projectId: number): Bytes | null {
  return unlocked.get(projectId) ?? null
}

/** Выход, конец сессии, другой пользователь: ключи прошлого входа не
 *  остаются в памяти вкладки. */
export function forgetAllKeys(): void {
  unlocked.clear()
}
