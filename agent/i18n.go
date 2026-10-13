package main

// Язык вывода агента: сообщения двуязычные, русский тем, кто его выбрал,
// остальным английский.
//
// Выбор по порядку: переменная SEKVYR_LANG (ru или en); русская локаль в
// LC_ALL, LC_MESSAGES или LANG; язык из конфига агента, который записывает
// установщик по языку панели, откуда взяли команду; иначе английский.
// Английская локаль русский из конфига не перебивает: на серверах она чаще
// стоит по умолчанию, чем выбрана человеком.

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

var russian = langFromEnv() == "ru"

// langFromEnv - язык, если его явно задало окружение, иначе пусто.
func langFromEnv() string {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("SEKVYR_LANG"))) {
	case "ru":
		return "ru"
	case "en":
		return "en"
	}
	for _, name := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		value := strings.ToLower(os.Getenv(name))
		if value == "" {
			continue
		}
		// Решает первая заданная переменная, как и у самой libc.
		if strings.HasPrefix(value, "ru") {
			return "ru"
		}
		return ""
	}
	return ""
}

// useConfigLang - язык из конфига, если окружение его не задало.
func useConfigLang(lang string) {
	if langFromEnv() != "" || lang == "" {
		return
	}
	russian = lang == "ru"
}

// peekConfigLang - язык из конфига по умолчанию еще до разбора флагов, чтобы
// и справка по флагам говорила на нем. Конфиг читает только root; у остальных
// остается язык окружения.
func peekConfigLang() {
	raw, err := os.ReadFile(defaultConfig)
	if err != nil {
		return
	}
	var cfg struct {
		Lang string `json:"lang"`
	}
	if json.Unmarshal(raw, &cfg) == nil {
		useConfigLang(cfg.Lang)
	}
}

// tr - строка на языке вывода.
func tr(ru, en string) string {
	if russian {
		return ru
	}
	return en
}

// keysCount - число ключей со словом на языке вывода: 1 ключ, 2 ключа,
// 5 ключей, 21 ключ; 1 key, 2 keys.
func keysCount(n int) string {
	if !russian {
		if n == 1 {
			return "1 key"
		}
		return fmt.Sprintf("%d keys", n)
	}
	word := "ключей"
	switch {
	case n%10 == 1 && n%100 != 11:
		word = "ключ"
	case n%10 >= 2 && n%10 <= 4 && (n%100 < 12 || n%100 > 14):
		word = "ключа"
	}
	return fmt.Sprintf("%d %s", n, word)
}
