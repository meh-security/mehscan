package fixture

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/dgrijalva/jwt-go"
	"go.mongodb.org/mongo-driver/bson"
)

func Handle(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	body, _ := io.ReadAll(r.Body)
	var filter bson.M
	_ = json.Unmarshal(body, &filter)
	models.Lookup(client, filter)
	_ = vars["id"]
	_ = r.URL.Query()["token"]
	_, _, _ = new(jwt.Parser).ParseUnverified("token", jwt.MapClaims{})
}

func OrdinaryJSON(body []byte) {
	var destination struct{ Name string }
	_ = json.Unmarshal(body, &destination)
}
