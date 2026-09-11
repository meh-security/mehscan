package fixture

import (
	"net/http"

	"github.com/gorilla/sessions"
)

var store = sessions.NewCookieStore([]byte(config.SessionKey))

func GetSession(r *http.Request, key string) string {
	session, _ := store.Get(r, "app")
	value := session.Values[key]
	return value.(string)
}

