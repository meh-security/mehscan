package fixture

import (
	"net/http"

	"github.com/julienschmidt/httprouter"
)

func Routes(router *httprouter.Router) {
	router.GET("/unsafe", mw.LoggingMiddleware(mw.AuthCheck(UnsafeHandler)))
	router.GET("/safe", mw.AuthCheck(SafeHandler))
}

func UnsafeHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	uid := GetCookie(r, "uid")
	_ = profile.UnsafeQuery(uid)
}

func GetCookie(r *http.Request, name string) string {
	cookie, _ := r.Cookie(name)
	return cookie.Value
}

func SafeHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	uid := r.FormValue("uid")
	_ = profile.SafeQuery(uid)
}
