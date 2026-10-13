package main

import "testing"

func TestKeysCount(t *testing.T) {
	was := russian
	defer func() { russian = was }()

	russian = true
	for n, want := range map[int]string{
		0: "0 ключей", 1: "1 ключ", 2: "2 ключа", 4: "4 ключа", 5: "5 ключей",
		11: "11 ключей", 12: "12 ключей", 14: "14 ключей", 21: "21 ключ",
		22: "22 ключа", 25: "25 ключей", 111: "111 ключей", 112: "112 ключей", 101: "101 ключ",
	} {
		if got := keysCount(n); got != want {
			t.Errorf("ru %d: got %q, want %q", n, got, want)
		}
	}

	russian = false
	for n, want := range map[int]string{0: "0 keys", 1: "1 key", 2: "2 keys", 21: "21 keys"} {
		if got := keysCount(n); got != want {
			t.Errorf("en %d: got %q, want %q", n, got, want)
		}
	}
}
