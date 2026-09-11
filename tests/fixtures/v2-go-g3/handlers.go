package fixture

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"html/template"
	"net/http"
)

func XSS(w http.ResponseWriter, r *http.Request) {
	term := r.FormValue("term")
	if HighMode(r) {
		term = HTMLEscapeString(term)
	}
	markup := fmt.Sprintf("<b>%s</b>", term)
	_ = template.HTML(markup)
}

func Update(w http.ResponseWriter, r *http.Request) {
	sid := GetSession(r, "id")
	uid := r.FormValue("uid")
	sign := r.FormValue("signature")
	expected := Md5Sum(uid)
	if sign == expected {
		if HighMode(r) {
			uid = sid
		}
		_ = profile.UpdateProfile("name", uid)
	}
}

func Login(r *http.Request) {
	password := Md5Sum(r.FormValue("password"))
	_ = password
}

func Verify(r *http.Request) bool {
	digest := "a587cd6bf1e49d2c3928d1f8b86f248b"
	otp := r.FormValue("otp")
	return digest == Md5Sum(otp)
}

func Md5Sum(value string) string {
	hasher := md5.New()
	hasher.Write([]byte(value))
	return hex.EncodeToString(hasher.Sum(nil))
}

func HTMLEscapeString(value string) string { return value }
func HighMode(r *http.Request) bool         { return false }

