package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey_Success(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey secret-token-123")

	got, err := GetAPIKey(headers)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if got != "secret-token-123" {
		t.Errorf("expected key %q, got %q", "secret-token-123", got)
	}
}

func TestGetAPIKey_NoAuthHeader(t *testing.T) {
	headers := http.Header{} // no Authorization

	_, err := GetAPIKey(headers)
	if err != ErrNoAuthHeaderIncluded {
		t.Fatalf("expected ErrNoAuthHeaderIncluded, got %v", err)
	}
}

func TestGetAPIKey_MalformedHeader(t *testing.T) {
	cases := []http.Header{
		// wrong prefix
		func() http.Header { h := http.Header{}; h.Set("Authorization", "Bearer abc"); return h }(),
		// missing token
		func() http.Header { h := http.Header{}; h.Set("Authorization", "ApiKey"); return h }(),
		// extra spaces but no token
		func() http.Header { h := http.Header{}; h.Set("Authorization", "ApiKey "); return h }(),
	}

	for i, headers := range cases {
		_, err := GetAPIKey(headers)
		if err == nil || err == ErrNoAuthHeaderIncluded {
			t.Errorf("case %d: expected malformed header error, got %v", i, err)
		}
	}
}
