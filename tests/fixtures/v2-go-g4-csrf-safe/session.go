package fixture

import "github.com/gorilla/sessions"

var store = sessions.NewCookieStore([]byte(config.SessionKey))

