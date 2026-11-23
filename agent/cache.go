package main

// Локальная копия значений - чтобы сервер поднимался без панели.
//
// Файл со значениями живет в tmpfs и после перезагрузки исчезает. Пока
// контейнер просто перезапускается, это неважно: docker запечатывает
// переменные внутрь контейнера при его создании. Но стоит пересоздать
// контейнер (деплой, `up -d`, `down && up`) при недоступной панели - и compose
// откажется стартовать: файла нет.
//
// Поэтому агент держит копию последних полученных значений на диске. При старте
// без связи он разворачивает её и продолжает стучаться в панель: сервис
// поднимается со вчерашними значениями вместо того, чтобы не подняться вовсе.
//
// Копия зашифрована ключом, выведенным из ключа ноды (`node.key`, права 0600):
// это не защита от root - у него и так есть все, - а защита от случайностей:
// утекшего бэкапа каталога, копии диска, любопытного взгляда в /var/lib.
// Кому и такая копия не нужна, выключает её флагом `--no-cache`.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const cacheInfo = "sekvyr-cache-v1"

// cached - то, что лежит в копии. Время нужно, чтобы сказать человеку, насколько
// старые значения он получил: "взял из кеша" без даты бесполезно.
type cached struct {
	Project     string  `json:"project"`
	Environment string  `json:"environment"`
	SavedAt     string  `json:"saved_at"`
	Values      []value `json:"values"`
}

// cacheDir - где лежат копии: там же, где ключ ноды.
func cacheDir(cfg *Config) string {
	if dir := os.Getenv("STATE_DIRECTORY"); dir != "" {
		return dir
	}
	if path := os.Getenv("SEKVYR_NODE_KEY"); path != "" {
		return filepath.Dir(path)
	}
	if serviceStateReadable() {
		return serviceState
	}
	return filepath.Dir(cfg.path)
}

// cacheScope is shared by the filename and the AEAD. Two agents may share a
// state directory and node key while using different panels or credentials.
func cacheScope(cfg *Config) [32]byte {
	identity := []string{strings.TrimRight(cfg.URL, "/"), cfg.Group, cfg.Project, cfg.Env}
	if cfg.TokenFile != "" {
		// Use the configured credential location so token renewal does not
		// invalidate the cache every time the projected token changes.
		identity = append(identity, "token-file", cfg.path, cfg.TokenFile)
	} else {
		identity = append(identity, "machine", cfg.ClientID)
	}
	encoded, _ := json.Marshal(identity)
	return sha256.Sum256(encoded)
}

func cachePath(cfg *Config) string {
	scope := cacheScope(cfg)
	return filepath.Join(cacheDir(cfg), "cache3-"+hex.EncodeToString(scope[:])+".bin")
}

func cacheKey(cfg *Config) ([]byte, error) {
	key, err := nodeKey(cfg.path)
	if err != nil {
		return nil, err
	}
	return hkdf32(key.Bytes(), []byte(cacheInfo)), nil
}

// saveCache перезаписывает копию. Ошибки не критичны: копия - удобство, а не
// обязательство, и падать из-за нее агент не должен.
func saveCache(cfg *Config, res *secretsResponse) error {
	key, err := cacheKey(cfg)
	if err != nil {
		return err
	}
	blob, err := json.Marshal(cached{
		Project:     res.Project,
		Environment: res.Environment,
		SavedAt:     time.Now().UTC().Format(time.RFC3339),
		Values:      res.Values,
	})
	if err != nil {
		return err
	}
	gcm, err := newGCM(key)
	if err != nil {
		return err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	scope := cacheScope(cfg)
	packed := append(nonce, gcm.Seal(nil, nonce, blob, scope[:])...)
	body := base64.StdEncoding.EncodeToString(packed)

	return writeFile(cachePath(cfg), body+"\n", 0o600)
}

// removeCache убирает копию значений приложения.
func removeCache(cfg *Config) {
	_ = os.Remove(cachePath(cfg))
}

// loadCache разворачивает копию. Возвращает ответ в том же виде, в каком его
// отдала бы панель, - вызывающему не нужно знать, откуда значения.
func loadCache(cfg *Config) (*secretsResponse, string, error) {
	// Older cache formats cannot prove which panel or machine issued them.
	raw, err := os.ReadFile(cachePath(cfg))
	if err != nil {
		return nil, "", err
	}
	key, err := cacheKey(cfg)
	if err != nil {
		return nil, "", err
	}
	packed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, "", fmt.Errorf(tr("копия значений испорчена: %w", "the copy of the values is damaged: %w"), err)
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, "", err
	}
	if len(packed) < gcm.NonceSize() {
		return nil, "", errors.New(tr("копия значений короче, чем должна быть", "the copy of the values is shorter than it should be"))
	}
	scope := cacheScope(cfg)
	blob, err := gcm.Open(nil, packed[:gcm.NonceSize()], packed[gcm.NonceSize():], scope[:])
	if err != nil {
		return nil, "", errors.New(tr("копия значений не раскрывается: неверный ключ или источник", "the copy of the values does not open: wrong key or source"))
	}
	var data cached
	if err := json.Unmarshal(blob, &data); err != nil {
		return nil, "", err
	}
	if data.Project != cfg.Project || data.Environment != cfg.Env {
		return nil, "", fmt.Errorf(tr("копия значений принадлежит %s/%s, а не этому приложению",
			"the copy of the values belongs to %s/%s, not to this application"), data.Project, data.Environment)
	}
	return &secretsResponse{
		Project:     data.Project,
		Environment: data.Environment,
		Values:      data.Values,
	}, data.SavedAt, nil
}

// fetchOrCache - значения из панели, а если её нет, из копии.
//
// Порядок именно такой: панель всегда главнее. Копия нужна ровно в одном
// случае - когда без нее сервис не поднимется вообще.
func fetchOrCache(cfg *Config, useCache bool) (*secretsResponse, error) {
	res, err := fetch(cfg)
	if err == nil {
		if useCache {
			if saveErr := saveCache(cfg, res); saveErr != nil {
				fmt.Fprintln(os.Stderr, tr("sekvyr: копию значений сохранить не вышло:", "sekvyr: could not save the copy of the values:"), saveErr)
			}
		}
		return res, nil
	}
	offline := unreachable(err)
	var refused *panelError
	if errors.As(err, &refused) && refused.code >= 400 && refused.code < 500 && !offline {
		// A later outage must not resurrect a copy the panel just denied,
		// even if this command was run with --no-cache.
		removeCache(cfg)
	}
	if !useCache || !offline {
		return nil, err
	}
	res, savedAt, cacheErr := loadCache(cfg)
	if cacheErr != nil {
		// Про панель говорим первым: это исходная причина, а отсутствие копии -
		// следствие, и вести человека надо к первой.
		return nil, fmt.Errorf(tr("%w (копии тоже нет: %v)", "%w (and there is no copy: %v)"), err, cacheErr)
	}
	fmt.Fprintf(os.Stderr, tr("sekvyr: панель недоступна (%v), значения взяты из копии от %s\n", "sekvyr: the panel is unreachable (%v), values taken from the copy of %s\n"), err, savedAt)
	return res, nil
}
