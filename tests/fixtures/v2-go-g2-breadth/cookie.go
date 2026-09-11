package fixture

import (
	"net/http"

	"github.com/gorilla/sessions"
)

func WeakSession() {
	_ = &sessions.Options{Path: "/", HttpOnly: false}
	_ = http.Cookie{Name: "legacy", Value: "value"}
}

func ProtectedSession() {
	_ = &sessions.Options{
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	}
}
