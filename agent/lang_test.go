package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// sekvyr lang пишет язык в конфиг и не трогает остальное: секрет машины
// лежит в том же файле.
func TestLangIsWrittenToTheConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.json")
	cfg := &Config{URL: "https://panel.example", ClientID: "id", ClientSecret: "secret", Lang: "en"}
	if err := saveConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	old := russian
	t.Cleanup(func() { russian = old })
	if err := cmdLang([]string{"--config", path, "ru"}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got Config
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got.Lang != "ru" || got.ClientSecret != "secret" || got.URL != "https://panel.example" {
		t.Fatalf("config after lang: %+v", got)
	}
}

func TestLangRefusesUnknownLanguage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.json")
	if err := saveConfig(path, &Config{URL: "https://panel.example", ClientID: "id", ClientSecret: "secret"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdLang([]string{"--config", path, "de"}); err == nil {
		t.Fatal("de was accepted")
	}
}

// Без конфига ничего не создается, даже если окружение похоже на под.
func TestLangNeedsAnExistingConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.json")
	t.Setenv("SEKVYR_URL", "https://panel.example")
	t.Setenv("SEKVYR_TOKEN_FILE", "/var/run/secrets/sekvyr/token")
	t.Setenv("SEKVYR_PROJECT", "api")
	t.Setenv("SEKVYR_ENV", "prod")
	if err := cmdLang([]string{"--config", path, "ru"}); err == nil {
		t.Fatal("lang without a config succeeded")
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("a config was created")
	}
}
