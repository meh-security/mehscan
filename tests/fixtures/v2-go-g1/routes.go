package fixture

import "github.com/gorilla/mux"

func Routes(router *mux.Router) {
	router.HandleFunc("/items/{id}", JSON(RequireAuth(controller.Handle))).Methods("POST")
}
