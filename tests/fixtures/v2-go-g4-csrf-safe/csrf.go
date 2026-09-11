package fixture

import "github.com/gorilla/csrf"

func Protect(handler http.Handler) http.Handler {
	return csrf.Protect([]byte(config.CsrfKey))(handler)
}

