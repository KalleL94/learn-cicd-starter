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
	cases := []struct {
		name    string
		headers http.Header
	}{
		{
			name: "wrong prefix",
			headers: func() http.Header {
				h := http.Header{}
				h.Set("Authorization", "Bearer abc")
				return h
			}(),
		},
		{
			name: "missing token",
			headers: func() http.Header {
				h := http.Header{}
				h.Set("Authorization", "ApiKey")
				return h
			}(),
		},
	}

	for _, c := range cases {
		_, err := GetAPIKey(c.headers)
		if err == nil || err == ErrNoAuthHeaderIncluded {
			t.Errorf("%s: expected malformed-header error, got %v", c.name, err)
		}
	}
}

func TestGetAPIKey_EmptyToken(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey ")

	got, err := GetAPIKey(headers)
	if err != nil {
		t.Fatalf("expected no error for empty token, got %v", err)
	}
	if got != "" {
		t.Errorf("expected empty key, got %q", got)
	}
}
