package fixture

import (
	"bytes"
	"net/http"

	jwt "github.com/dgrijalva/jwt-go"
)

func ExtractToken(r *http.Request) string {
	query := r.URL.Query()
	return query.Get("token")
}

func ExtractTokenID(r *http.Request, db any) error {
	tokenString := ExtractToken(r)
	resp, _ := http.Post(verifyURL, "application/json", bytes.NewBuffer(nil))
	tokenValid := resp.StatusCode == 200
	token, _, _ := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	claims, ok := token.Claims.(jwt.MapClaims)
	if ok && tokenValid {
		return CheckTokenInDB(claims["sub"], db)
	}
	return errUnauthorized
}
