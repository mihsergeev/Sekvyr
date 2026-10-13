package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// enroll --force на то же окружение оставляет приложению его файл, команду и
// права: умолчания выдачи молча переводили его в /run/sekvyr и запускали
// compose, которого на ноде нет. Новое окружение того же проекта получает
// свой файл, а не файл сохраненного приложения.
func TestEnrollForceKeepsAppSettings(t *testing.T) {
	runDir = t.TempDir()
	defer func() { runDir = "/run/sekvyr" }()
	grant := map[string]string{"project": "shop", "env": "prod"}
	panel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"client_id": "skv-new", "client_secret": "s", "name": "node",
			"project": grant["project"], "env": grant["env"],
		})
	}))
	defer panel.Close()

	path := testConfig(t,
		App{Project: "shop", Env: "prod", Out: "/srv/shop/.env", OnChange: "systemctl reload shop", Mode: "440"},
		App{Project: "shop", Env: "stage"},
	)
	if err := cmdEnroll([]string{"--url", panel.URL, "--token", "t", "--config", path, "--force"}); err != nil {
		t.Fatal(err)
	}
	apps := savedApps(t, path)
	var prod *App
	for i := range apps {
		if apps[i].Project == "shop" && apps[i].Env == "prod" {
			prod = &apps[i]
		}
	}
	if len(apps) != 2 || prod == nil || prod.Out != "/srv/shop/.env" || prod.OnChange != "systemctl reload shop" || prod.Mode != "440" {
		t.Fatalf("настройки потеряны: %+v", apps)
	}

	// Новая выдача - другое окружение того же проекта: файл по умолчанию уже
	// у сохраненного shop/stage.
	grant["env"] = "qa"
	path = testConfig(t, App{Project: "shop", Env: "stage"})
	if err := cmdEnroll([]string{"--url", panel.URL, "--token", "t", "--config", path, "--force"}); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{}
	defer func() {
		// Проект старого вида (на верхнем уровне) тоже не пропадает: его
		// перенесет normalize при старте службы.
		legacy := testConfig(t)
		cfg, err := loadConfig(legacy)
		if err != nil {
			t.Fatal(err)
		}
		cfg.Project, cfg.Env = "billing", "prod"
		if err := saveConfig(legacy, cfg); err != nil {
			t.Fatal(err)
		}
		if err := cmdEnroll([]string{"--url", panel.URL, "--token", "t", "--config", legacy, "--force"}); err != nil {
			t.Fatal(err)
		}
		after, err := loadConfig(legacy)
		if err != nil {
			t.Fatal(err)
		}
		if after.Project != "billing" || after.Env != "prod" {
			t.Fatalf("проект старого вида потерян: %+v", after)
		}
	}()
	for _, app := range savedApps(t, path) {
		out := app.withFile().Out
		if other, taken := files[out]; taken {
			t.Fatalf("%s и %s пишут один файл %s", other, app.name(), out)
		}
		files[out] = app.name()
	}
}
