package main

import "testing"

// Записи сверены с настоящим docker compose (env_file): значение из файла
// доходит до приложения тем же, каким его задали. Те же случаи проверяет
// backend/tests/test_env_format.py для выгрузки из панели.
func TestQuote(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", `""`},
		{"plain", "plain"},
		{"user@db:5432/app", "user@db:5432/app"},
		{"P@ss$word1", "'P@ss$word1'"},
		{"a b", "'a b'"},
		{"a;rm -rf /", "'a;rm -rf /'"},
		{"https://x/y?a=1&b=2", "'https://x/y?a=1&b=2'"},
		{"пароль", "'пароль'"},
		{"`cmd`", "'`cmd`'"},
		{"line one\nline two", "'line one\nline two'"},
		{`C:\path\to`, `'C:\path\to'`},
		{`ends\`, `"ends\\"`},
		{"it's $5", `"it's \$5"`},
		{"it's `cmd`", "\"it's `cmd`\""},
		{"a\"b'c", `"a\"b'c"`},
		{"cr\rx", `"cr\rx"`},
		{"<?php\nreturn ['db' => $x];\n", "\"<?php\nreturn ['db' => \\$x];\n\""},
	}
	for _, c := range cases {
		if got := quote(c.in); got != c.want {
			t.Errorf("quote(%q) = %q, ожидалось %q", c.in, got, c.want)
		}
	}
}
