package fixture

import (
	"html/template"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/unrolled/secure"
)

type View struct {
	Search string
}

var key = []byte(os.Getenv("SESSION_KEY"))
var store = sessions.NewCookieStore(key)

func routes() {
	router := mux.NewRouter()
	security := secure.New(secure.Options{FrameDeny: true})
	router.Handle("/login", security.Handler(http.HandlerFunc(login)))
	router.Handle("/search", security.Handler(http.HandlerFunc(search)))
	router.Handle("/friends/add/{person}", security.Handler(http.HandlerFunc(addFriend))).Methods("POST")
}

func login(w http.ResponseWriter, r *http.Request) {
	password := r.FormValue("password")
	if !verifyPassword(password) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	session, _ := store.Get(r, "fixture")
	session.Options = &sessions.Options{HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode}
	session.Values["authenticated"] = true
	session.Save(r, w)
}

func search(w http.ResponseWriter, r *http.Request) {
	search := r.FormValue("search")
	view := View{Search: search}
	tmpl, _ := template.ParseFiles("templates/search.html")
	tmpl.Execute(w, view)
}

func addFriend(w http.ResponseWriter, r *http.Request) {}
func verifyPassword(password string) bool { return password == "runtime-secret" }
