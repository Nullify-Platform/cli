package auth

import (
	"net/http"
	"sync"
)

type cliCallback struct {
	SessionID        string `json:"session_id"`
	RedemptionSecret string `json:"redemption_secret"`
}

func newLoginCallbackHandler(sessionID string, callbacks chan<- cliCallback) http.Handler {
	var once sync.Once
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		query := r.URL.Query()
		if sessionID == "" || len(query["session_id"]) != 1 || query.Get("session_id") != sessionID {
			http.Error(w, "invalid session", http.StatusForbidden)
			return
		}
		secret := query.Get("redemption_secret")
		if len(query["redemption_secret"]) != 1 || !validRedemptionSecret(secret) {
			http.Error(w, "invalid redemption secret", http.StatusBadRequest)
			return
		}
		once.Do(func() { callbacks <- cliCallback{SessionID: sessionID, RedemptionSecret: secret} })
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("Callback received. Return to your terminal to check authentication completed. You can close this tab."))
	})
}

func validRedemptionSecret(secret string) bool {
	if len(secret) != 64 {
		return false
	}
	for _, c := range secret {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
