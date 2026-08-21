package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// newAuthServer points the package's auth calls at h and isolates the
// credential store, which SaveHostCredentials writes under os.UserHomeDir().
func newAuthServer(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(h)
	oldBase, oldClient := authBaseURL, httpClient
	authBaseURL = func(string) string { return srv.URL }
	httpClient = srv.Client()
	t.Cleanup(func() {
		authBaseURL, httpClient = oldBase, oldClient
		srv.Close()
	})
	t.Setenv("HOME", t.TempDir())
	return srv
}

// refreshHandler mirrors what GET /auth/refresh_token actually returns: the
// access token only as a Set-Cookie header, with the metadata in the body.
// See setCookies and RefreshTokenOutput in auth/pkg/endpoints.
func refreshHandler(w http.ResponseWriter, _ *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    "new-id-token",
		MaxAge:   3600,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteNoneMode,
	})
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"expiresIn":3600,"installationIds":[],"expiresAt":1,` +
		`"queryParameters":{"githubOwnerId":"42"},"isTriaged":false,"isNullifyDev":false}`))
}

func TestRefreshTokenReadsSetCookie(t *testing.T) {
	newAuthServer(t, refreshHandler)

	got, err := refreshToken(context.Background(), "example.nullify.ai", "stored-refresh")
	if err != nil {
		t.Fatalf("refreshToken: %v", err)
	}
	if got != "new-id-token" {
		t.Fatalf("token = %q, want new-id-token", got)
	}

	creds, err := LoadCredentials()
	if err != nil {
		t.Fatalf("LoadCredentials: %v", err)
	}
	saved := creds[CredentialKey("example.nullify.ai")]
	if saved.AccessToken != "new-id-token" {
		t.Errorf("saved AccessToken = %q, want new-id-token", saved.AccessToken)
	}
	// The endpoint does not rotate the refresh cookie, so the stored one must
	// survive or every later refresh fails.
	if saved.RefreshToken != "stored-refresh" {
		t.Errorf("saved RefreshToken = %q, want stored-refresh", saved.RefreshToken)
	}
	if d := saved.ExpiresAt - time.Now().Unix(); d < 3500 || d > 3600 {
		t.Errorf("ExpiresAt delta = %ds, want ~3600", d)
	}
	if saved.QueryParameters["githubOwnerId"] != "42" {
		t.Errorf("saved QueryParameters = %v, want githubOwnerId=42", saved.QueryParameters)
	}
}

func TestRefreshTokenBodyTokenWins(t *testing.T) {
	newAuthServer(t, func(w http.ResponseWriter, _ *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "access_token", Value: "cookie-token", MaxAge: 3600})
		_, _ = w.Write([]byte(`{"accessToken":"body-token","expiresIn":60}`))
	})

	got, err := refreshToken(context.Background(), "example.nullify.ai", "rt")
	if err != nil {
		t.Fatalf("refreshToken: %v", err)
	}
	if got != "body-token" {
		t.Errorf("token = %q, want body-token to take precedence", got)
	}
}

func TestRefreshTokenIgnoresEmptyCookie(t *testing.T) {
	newAuthServer(t, func(w http.ResponseWriter, _ *http.Request) {
		// A cleared cookie ahead of the live one must not win.
		http.SetCookie(w, &http.Cookie{Name: "access_token", Value: "", MaxAge: -1})
		http.SetCookie(w, &http.Cookie{Name: "access_token", Value: "real-token", MaxAge: 3600})
		_, _ = w.Write([]byte(`{"expiresIn":3600}`))
	})

	got, err := refreshToken(context.Background(), "example.nullify.ai", "rt")
	if err != nil {
		t.Fatalf("refreshToken: %v", err)
	}
	if got != "real-token" {
		t.Errorf("token = %q, want real-token", got)
	}
}

func TestRefreshTokenExpiresFallback(t *testing.T) {
	newAuthServer(t, func(w http.ResponseWriter, _ *http.Request) {
		// Max-Age absent: the lifetime must come from Expires rather than
		// collapsing to an already-expired credential.
		http.SetCookie(w, &http.Cookie{
			Name:    "access_token",
			Value:   "expires-token",
			Expires: time.Now().Add(time.Hour),
		})
		_, _ = w.Write([]byte(`{}`))
	})

	if _, err := refreshToken(context.Background(), "example.nullify.ai", "rt"); err != nil {
		t.Fatalf("refreshToken: %v", err)
	}

	creds, err := LoadCredentials()
	if err != nil {
		t.Fatalf("LoadCredentials: %v", err)
	}
	if d := creds[CredentialKey("example.nullify.ai")].ExpiresAt - time.Now().Unix(); d < 3500 {
		t.Errorf("ExpiresAt delta = %ds, want ~3600 from the Expires attribute", d)
	}
}

func TestRefreshTokenNoTokenAnywhere(t *testing.T) {
	newAuthServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"expiresIn":3600}`))
	})

	_, err := refreshToken(context.Background(), "example.nullify.ai", "rt")
	if err == nil {
		t.Fatal("want an error when neither body nor cookie carries a token")
	}
}

func TestRefreshTokenNon200(t *testing.T) {
	newAuthServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})

	_, err := refreshToken(context.Background(), "example.nullify.ai", "rt")
	if err == nil {
		t.Fatal("want an error on a non-200 refresh")
	}
}

func TestGetValidTokenReturnsStoredTokenWhenUnexpired(t *testing.T) {
	newAuthServer(t, func(http.ResponseWriter, *http.Request) {
		t.Error("refresh must not be attempted while the token is still valid")
	})
	seed(t, "example.nullify.ai", "live-token", "rt", time.Now().Add(time.Hour).Unix())

	got, err := GetValidToken(context.Background(), "example.nullify.ai")
	if err != nil {
		t.Fatalf("GetValidToken: %v", err)
	}
	if got != "live-token" {
		t.Errorf("token = %q, want live-token", got)
	}
}

func TestGetValidTokenRefreshesWhenExpired(t *testing.T) {
	newAuthServer(t, refreshHandler)
	seed(t, "example.nullify.ai", "old-token", "rt", time.Now().Add(-time.Hour).Unix())

	got, err := GetValidToken(context.Background(), "example.nullify.ai")
	if err != nil {
		t.Fatalf("GetValidToken: %v", err)
	}
	if got != "new-id-token" {
		t.Errorf("token = %q, want the refreshed new-id-token", got)
	}
}

// ForceRefreshToken exists so a caller holding a token the server rejects can
// get a new one even though the stored expiry still looks valid.
func TestForceRefreshTokenIgnoresUnexpiredCredential(t *testing.T) {
	newAuthServer(t, refreshHandler)
	seed(t, "example.nullify.ai", "revoked-token", "rt", time.Now().Add(time.Hour).Unix())

	got, err := ForceRefreshToken(context.Background(), "example.nullify.ai")
	if err != nil {
		t.Fatalf("ForceRefreshToken: %v", err)
	}
	if got != "new-id-token" {
		t.Errorf("token = %q, want new-id-token", got)
	}
}

func TestForceRefreshTokenWithoutRefreshToken(t *testing.T) {
	newAuthServer(t, func(http.ResponseWriter, *http.Request) {
		t.Error("refresh must not be attempted without a stored refresh token")
	})
	seed(t, "example.nullify.ai", "tok", "", time.Now().Add(time.Hour).Unix())

	_, err := ForceRefreshToken(context.Background(), "example.nullify.ai")
	if !errors.Is(err, ErrNotRefreshable) {
		t.Fatalf("err = %v, want ErrNotRefreshable", err)
	}
}

func seed(t *testing.T, host, access, refresh string, expiresAt int64) {
	t.Helper()
	err := SaveHostCredentials(host, HostCredentials{
		AccessToken:  access,
		RefreshToken: refresh,
		ExpiresAt:    expiresAt,
	})
	if err != nil {
		t.Fatalf("seed credentials: %v", err)
	}
}
