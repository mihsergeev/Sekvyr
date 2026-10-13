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
	"encoding/base64"
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

// cachePath - своя копия на каждое окружение: на сервере может быть несколько
// приложений, и общий файл они бы затирали друг другу.
//
// Части имени разделены плюсом: в именах бывают только буквы, цифры и дефис.
// Прежняя склейка дефисом давала одно имя для shop-eu/prod и shop/eu-prod, и
// при лежащей панели одно приложение получало значения другого. Группа входит
// в имя: frontend/prod бывает и у globex, и у initech.
func cachePath(cfg *Config) string {
	name := cfg.Project + "+" + cfg.Env
	if cfg.Group != "" {
		name = cfg.Group + "+" + name
	}
	return filepath.Join(cacheDir(cfg), "cache2-"+name+".bin")
}

// oldCachePath - имя копии до версии с плюсами. Такие копии читаются, пока
// новая не записана, но только после сверки проекта и окружения внутри.
func oldCachePath(cfg *Config) string {
	name := cfg.Project + "-" + cfg.Env
	if cfg.Group != "" {
		name = cfg.Group + "+" + name
	}
	return filepath.Join(cacheDir(cfg), "cache-"+name+".bin")
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
	packed := append(nonce, gcm.Seal(nil, nonce, blob, nil)...)
	body := base64.StdEncoding.EncodeToString(packed)

	path := cachePath(cfg)
	// Тем же путем, что файл со значениями: с fsync. Копия переписывается
	// каждую минуту, и без него обесточенный целиком ЦОД оставлял ее пустой
	// ровно тогда, когда без нее не обойтись. Имя .tmp - от прежних версий.
	_ = os.Remove(path + ".tmp")
	if err := writeFile(path, body+"\n", 0o600); err != nil {
		return err
	}
	// Копию со старым именем, если она этого же приложения, больше не держим:
	// иначе старые значения лежали бы на диске всегда.
	if _, _, err := readCache(oldCachePath(cfg), cfg); err == nil {
		_ = os.Remove(oldCachePath(cfg))
	}
	return nil
}

// removeCache убирает копию значений приложения.
func removeCache(cfg *Config) {
	_ = os.Remove(cachePath(cfg))
	// Старое имя склеивалось дефисом и бывает общим у shop/eu-prod и
	// shop-eu/prod: убираем, только если копия наша.
	if _, _, err := readCache(oldCachePath(cfg), cfg); err == nil {
		_ = os.Remove(oldCachePath(cfg))
	}
}

// loadCache разворачивает копию. Возвращает ответ в том же виде, в каком его
// отдала бы панель, - вызывающему не нужно знать, откуда значения.
func loadCache(cfg *Config) (*secretsResponse, string, error) {
	res, savedAt, err := readCache(cachePath(cfg), cfg)
	if errors.Is(err, os.ErrNotExist) {
		return readCache(oldCachePath(cfg), cfg)
	}
	return res, savedAt, err
}

// readCache разворачивает одну копию и сверяет, чья она: имя файла - не
// доказательство, а отдать приложению значения другого хуже, чем ничего.
func readCache(path string, cfg *Config) (*secretsResponse, string, error) {
	raw, err := os.ReadFile(path)
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
	blob, err := gcm.Open(nil, packed[:gcm.NonceSize()], packed[gcm.NonceSize():], nil)
	if err != nil {
		// Обычно это значит, что ключ ноды сменился: старую копию уже не
		// прочитать, и держаться за нее незачем.
		return nil, "", errors.New(tr("копия значений не раскрывается: ключ ноды сменился", "the copy of the values does not open: the node key has changed"))
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
	if !useCache || !unreachable(err) {
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
