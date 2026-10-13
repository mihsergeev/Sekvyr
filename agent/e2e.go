package main

// Проекты, значения которых панель не видит.
//
// Значение приходит на ноду запечатанным ключом проекта, а сам ключ - в
// обертке на публичный ключ этой ноды. Панель хранит и то и другое, но раскрыть
// не может: у нее нет ни ключа проекта, ни приватного ключа ноды.
//
// Как выглядит обмен:
//
//  1. Агент при первом обращении заводит пару P-256 и присылает публичную
//     половину в отчете. Приватная лежит рядом с конфигом, правами 0600, и
//     никуда не уезжает.
//  2. Человек в браузере, где есть ключ проекта, запечатывает его на этот
//     публичный ключ и кладет обертку в панель.
//  3. Агент делает ECDH со своим приватным ключом, выводит ключ обертки через
//     HKDF и достает ключ проекта. Дальше значения открываются как обычно.
//
// Кривая P-256, а не X25519: её умеет и WebCrypto во всех браузерах, и
// стандартная библиотека Go. Браузер здесь обязательный участник, поэтому
// выбор кривой определяется им.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Метка запечатанного значения. Такая же, как в панели и в браузере.
const sealedPrefix = "e2e1:"

// Контекст выведения ключа обертки. Должен совпадать с браузером буква в букву:
// разойдутся - обертка не раскроется, и понять почему будет нечем.
const wrapInfo = "sekvyr-e2e-machine-v1"

// projectKey - то, что панель присылает вместе со значениями e2e-проекта.
type projectKey struct {
	Nonce           string `json:"nonce"`
	WrappedKey      string `json:"wrapped_key"`
	EphemeralPublic string `json:"ephemeral_public"`
}

// keyPath - где лежит приватный ключ ноды.
//
// Порядок неслучаен. Служба systemd работает с ProtectSystem=strict, то есть
// /etc для нее только на чтение: класть ключ рядом с конфигом там нельзя, и
// первая живая проверка это показала. Поэтому сначала спрашиваем каталог
// состояния, который systemd создает сам (StateDirectory=sekvyr), потом явную
// переменную, и только затем - соседство с конфигом, как в контейнере, где
// systemd нет вовсе.
func keyPath(configPath string) string {
	if path := os.Getenv("SEKVYR_NODE_KEY"); path != "" {
		return path
	}
	if dir := os.Getenv("STATE_DIRECTORY"); dir != "" {
		return filepath.Join(dir, "node.key")
	}
	if serviceStateReadable() {
		return filepath.Join(serviceState, "node.key")
	}
	return filepath.Join(filepath.Dir(configPath), "node.key")
}

// serviceState - каталог состояния службы (StateDirectory=sekvyr в юните).
const serviceState = "/var/lib/sekvyr"

// serviceStateReadable - есть ли ключ службы и читается ли он. Разовая команда
// из консоли (sudo sekvyr render, sekvyr run в своем юните) не получает
// STATE_DIRECTORY и раньше брала ключ рядом с конфигом: другой ключ ноды,
// отдельную копию значений, а для e2e-проекта отказ "обертка сделана для
// другого ключа", который повторная выдача не лечила.
func serviceStateReadable() bool {
	f, err := os.Open(filepath.Join(serviceState, "node.key"))
	if err != nil {
		return false
	}
	f.Close()
	return true
}

// nodeKey возвращает приватный ключ ноды, заводя его при первом обращении.
func nodeKey(configPath string) (*ecdh.PrivateKey, error) {
	path := keyPath(configPath)
	raw, err := os.ReadFile(path)
	if err == nil {
		decoded, decodeErr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
		if decodeErr != nil {
			return nil, fmt.Errorf(tr("ключ ноды %s испорчен: %w", "the node key %s is damaged: %w"), path, decodeErr)
		}
		return ecdh.P256().NewPrivateKey(decoded)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	body := base64.StdEncoding.EncodeToString(key.Bytes())
	// Через временный файл: обрыв записи (кончилось место) оставлял пустой
	// node.key, и дальше навсегда "invalid private key size".
	if err := writeFile(path, body+"\n", 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

// nodePublicKey - то, что агент присылает панели. Секретом не является.
func nodePublicKey(configPath string) (string, error) {
	key, err := nodeKey(configPath)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}

// unwrapProjectKey достает ключ проекта из обертки, сделанной браузером.
func unwrapProjectKey(configPath string, wrap *projectKey) ([]byte, error) {
	if wrap == nil {
		return nil, errors.New(tr("панель не прислала ключ проекта: выдайте его этой машине", "the panel sent no project key: grant it to this machine"))
	}
	key, err := nodeKey(configPath)
	if err != nil {
		return nil, err
	}
	theirBytes, err := base64.StdEncoding.DecodeString(wrap.EphemeralPublic)
	if err != nil {
		return nil, fmt.Errorf(tr("эфемерный ключ не разобрался: %w", "the ephemeral key could not be parsed: %w"), err)
	}
	theirs, err := ecdh.P256().NewPublicKey(theirBytes)
	if err != nil {
		return nil, fmt.Errorf(tr("эфемерный ключ не годится: %w", "the ephemeral key is not usable: %w"), err)
	}
	shared, err := key.ECDH(theirs)
	if err != nil {
		return nil, err
	}

	wrapper := hkdf32(shared, []byte(wrapInfo))
	nonce, err := base64.StdEncoding.DecodeString(wrap.Nonce)
	if err != nil {
		return nil, fmt.Errorf(tr("nonce обёртки не разобрался: %w", "the wrapping nonce could not be parsed: %w"), err)
	}
	blob, err := base64.StdEncoding.DecodeString(wrap.WrappedKey)
	if err != nil {
		return nil, fmt.Errorf(tr("обёртка не разобралась: %w", "the wrapping could not be parsed: %w"), err)
	}
	gcm, err := newGCM(wrapper)
	if err != nil {
		return nil, err
	}
	// gcm.Open с nonce другой длины не возвращает ошибку, а роняет процесс:
	// испорченная или подмененная обертка остановила бы агента целиком.
	if len(nonce) != gcm.NonceSize() {
		return nil, errors.New(tr("nonce обертки не того размера", "the wrapping nonce has the wrong size"))
	}
	plain, err := gcm.Open(nil, nonce, blob, nil)
	if err != nil {
		// Чаще всего это значит, что ключ ноды сменился, а обертку не выдали
		// заново. Сообщение должно вести к этой мысли, а не к "ошибке шифра".
		return nil, errors.New(tr(
			"ключ проекта не раскрывается: похоже, обёртка сделана для другого ключа ноды — "+
				"выдайте ключ проекта этой машине заново",
			"the project key does not open: the wrapping seems to be made for another node key, "+
				"grant the project key to this machine again"))
	}
	return plain, nil
}

// openSealed раскрывает одно значение ключом проекта.
func openSealed(key []byte, sealed string) (string, error) {
	if !strings.HasPrefix(sealed, sealedPrefix) {
		// Панель уже сказала, что проект e2e; значение без метки означает
		// рассогласование, и молча отдавать его приложению нельзя.
		return "", errors.New(tr("значение пришло незапечатанным, хотя проект зашифрован", "a value arrived unsealed although the project is encrypted"))
	}
	packed, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(sealed, sealedPrefix))
	if err != nil {
		return "", fmt.Errorf(tr("значение не разобралось: %w", "a value could not be parsed: %w"), err)
	}
	gcm, err := newGCM(key)
	if err != nil {
		return "", err
	}
	if len(packed) < gcm.NonceSize() {
		return "", errors.New(tr("значение короче, чем должно быть", "a value is shorter than it should be"))
	}
	plain, err := gcm.Open(nil, packed[:gcm.NonceSize()], packed[gcm.NonceSize():], nil)
	if err != nil {
		return "", errors.New(tr("значение не раскрывается: не тот ключ проекта", "a value does not open: wrong project key"))
	}
	return string(plain), nil
}

// hkdf32 - HKDF-SHA256 на 32 байта, ровно как его делает WebCrypto с пустой
// солью. Своя реализация вместо зависимости: у агента в go.mod нет ни одного
// внешнего модуля, и ради двадцати строк ломать это правило не стоит.
func hkdf32(secret, info []byte) []byte {
	extract := hmac.New(sha256.New, make([]byte, sha256.Size))
	extract.Write(secret)
	prk := extract.Sum(nil)

	expand := hmac.New(sha256.New, prk)
	expand.Write(info)
	expand.Write([]byte{1})
	return expand.Sum(nil)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// diskless - отпечатки ключей проектов, которые не удалось записать на диск
// (под в кластере с диском только для чтения): там защита держится хотя бы до
// перезапуска. Где отметка на диске есть, главная она: удаленная человеком
// отметка действует сразу, без перезапуска службы.
var diskless = map[string]string{}

// e2eMarker - отметка проекта этой панели. Адрес панели входит в имя: сервер,
// который на время переезда подключен к двум панелям с проектом-тезкой, иначе
// получал бы ложный отказ.
func e2eMarker(cfg *Config) string {
	name := cfg.Project
	if cfg.Group != "" {
		name = cfg.Group + "+" + name
	}
	panel := sha256.Sum256([]byte(strings.TrimRight(cfg.URL, "/")))
	return filepath.Join(cacheDir(cfg), "e2e-"+name+"-"+hex.EncodeToString(panel[:4])+".seen")
}

// keyPrint - отпечаток ключа проекта для отметки. Сам ключ на диск не идет.
func keyPrint(key []byte) string {
	sum := sha256.Sum256(append([]byte("sekvyr-e2e-key-print\x00"), key...))
	return hex.EncodeToString(sum[:16])
}

// checkE2E: проект, который однажды пришел зашифрованным в браузере,
// зашифрован навсегда, и ключ его не меняется - ни выключить режим, ни сменить
// ключ проекта в панели нельзя. Поэтому подмененная или захваченная панель не
// подсунет свои значения (адрес своей базы вместо настоящего) ни ответом
// "проект не зашифрован", ни своим ключом проекта: публичный ключ ноды у нее
// есть, и обернуть на него свой ключ она могла бы. key - отпечаток ключа из
// ответа, пусто для незашифрованного.
func checkE2E(cfg *Config, key string) error {
	marker := e2eMarker(cfg)
	known, seen := diskless[marker]
	if raw, err := os.ReadFile(marker); err == nil {
		known, seen = strings.TrimSpace(string(raw)), true
	}
	switch {
	case key == "" && seen:
		return fmt.Errorf(tr(
			"панель отдала проект %s открытым, хотя он зашифрован в браузере: значения не применены. Если проект в панели правда заведен заново без шифрования, удалите %s",
			"the panel sent project %s unencrypted although it is encrypted in the browser: the values were not applied. If the project was really recreated in the panel without encryption, delete %s"),
			cfg.Project, marker)
	case key != "" && seen && known != "" && known != key:
		return fmt.Errorf(tr(
			"ключ проекта %s не тот, что был: значения не применены. Если проект в панели правда заведен заново, удалите %s",
			"the key of project %s is not the one it was: the values were not applied. If the project was really recreated in the panel, delete %s"),
			cfg.Project, marker)
	case key != "" && known != key:
		if err := writeFile(marker, key+"\n", 0o600); err != nil {
			diskless[marker] = key
		} else {
			delete(diskless, marker)
		}
	}
	return nil
}

// openAll раскрывает все значения ответа. Ошибка на любом - общий отказ:
// половина файла хуже, чем понятная ошибка, потому что приложение поднимется
// и будет вести себя странно.
//
// Возвращает отпечаток ключа проекта (пусто, если проект не зашифрован): по
// нему checkE2E узнает подмену ключа.
func openAll(configPath string, res *secretsResponse) (string, error) {
	if !res.E2E {
		return "", nil
	}
	key, err := unwrapProjectKey(configPath, res.ProjectKey)
	if err != nil {
		return "", err
	}
	for i := range res.Values {
		plain, err := openSealed(key, res.Values[i].Value)
		if err != nil {
			return "", fmt.Errorf("%s: %w", res.Values[i].Name, err)
		}
		res.Values[i].Value = plain
	}
	return keyPrint(key), nil
}
