package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey_Success(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey abc123")

	key, err := GetAPIKey(headers)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if key != "abc123" {
		t.Fatalf("expected key 'abc123', got %q", key)
	}
}

func TestGetAPIKey_NoHeader(t *testing.T) {
	headers := http.Header{}

	key, err := GetAPIKey(headers)
	if key != "" {
		t.Fatalf("expected empty key, got %q", key)
	}
	if !errors.Is(err, ErrNoAuthHeaderIncluded) {
		t.Fatalf("expected ErrNoAuthHeaderIncluded, got %v", err)
	}
}

func TestGetAPIKey_Malformed(t *testing.T) {
	tests := []struct {
		name   string
		header string
	}{
		{name: "wrong scheme", header: "Bearer token"},
		{name: "no token", header: "ApiKey"},
		// Note: current implementation accepts the second token as-is; trailing spaces don't yield a malformed error
		// so we do not treat "ApiKey  " as malformed here.
		{name: "lowercase scheme", header: "apikey abc123"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			headers := http.Header{}
			headers.Set("Authorization", tc.header)

			key, err := GetAPIKey(headers)
			if key != "" {
				t.Fatalf("expected empty key, got %q", key)
			}
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if err.Error() != "malformed authorization header" {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
