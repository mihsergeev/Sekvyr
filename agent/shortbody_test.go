package main

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestShortBodyTurnsProxyPageIntoCodeName(t *testing.T) {
	page := "<html>\n<head><title>502 Bad Gateway</title></head>\n<body>\n<center><h1>502 Bad Gateway</h1></center>\n</body>\n</html>\n"
	if got := shortBody([]byte(page), 502); got != "Bad Gateway" {
		t.Fatalf("got %q", got)
	}
	if got := shortBody(nil, 503); got != "Service Unavailable" {
		t.Fatalf("got %q", got)
	}
}

func TestShortBodyIsOneLineAndCutByLetters(t *testing.T) {
	got := shortBody([]byte("первая\n  вторая\tтретья"), 500)
	if got != "первая вторая третья" {
		t.Fatalf("got %q", got)
	}
	long := shortBody([]byte(strings.Repeat("я", 400)), 500)
	if !utf8.ValidString(long) || utf8.RuneCountInString(long) != 303 {
		t.Fatalf("cut badly: %d runes, valid %v", utf8.RuneCountInString(long), utf8.ValidString(long))
	}
}
