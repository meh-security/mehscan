package fixture

import (
	"net/http"

	"github.com/julienschmidt/httprouter"
)

func Routes(router *httprouter.Router) {
	router.POST("/profile", mw.AuthCheck(UpdateHandler))
}

func UpdateHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	uid := r.FormValue("uid")
	_ = profile.UpdateProfile("name", uid)
}

