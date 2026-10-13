package main

import "testing"

func TestLanguageChoice(t *testing.T) {
	cases := []struct {
		name   string
		env    map[string]string
		config string
		want   bool // russian
	}{
		{"по умолчанию английский", nil, "", false},
		{"русская локаль", map[string]string{"LANG": "ru_RU.UTF-8"}, "", true},
		{"LC_ALL главнее LANG", map[string]string{"LC_ALL": "C.UTF-8", "LANG": "ru_RU.UTF-8"}, "", false},
		{"язык из конфига", map[string]string{"LANG": "C.UTF-8"}, "ru", true},
		{"английская локаль конфиг не перебивает", map[string]string{"LANG": "en_US.UTF-8"}, "ru", true},
		{"SEKVYR_LANG главнее конфига", map[string]string{"SEKVYR_LANG": "en"}, "ru", false},
		{"SEKVYR_LANG главнее локали", map[string]string{"SEKVYR_LANG": "ru", "LANG": "en_US.UTF-8"}, "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for _, name := range []string{"SEKVYR_LANG", "LC_ALL", "LC_MESSAGES", "LANG"} {
				t.Setenv(name, c.env[name])
			}
			russian = langFromEnv() == "ru"
			useConfigLang(c.config)
			if russian != c.want {
				t.Fatalf("russian = %v, want %v", russian, c.want)
			}
		})
	}
	russian = false
}

func TestPanelRefusalsAreTranslated(t *testing.T) {
	russian = false
	if got := apiError("Этой машине окружение не выдано"); got != "this machine has not been granted the environment" {
		t.Fatalf("got %q", got)
	}
	// незнакомый ответ показывается как есть
	if got := apiError("что-то новое"); got != "что-то новое" {
		t.Fatalf("got %q", got)
	}
	russian = true
	if got := apiError("Этой машине окружение не выдано"); got != "Этой машине окружение не выдано" {
		t.Fatalf("got %q", got)
	}
	russian = false
}
