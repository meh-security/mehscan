package fixture

import (
	"net/http"
	"text/template"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/unrolled/secure"
)

type View struct {
	Search string
}

type Person struct {
	Name string
}

var key = []byte("01234567890123456789012345678901")
var store = sessions.NewCookieStore(key)

func routes() {
	router := mux.NewRouter()
	security := secure.New(secure.Options{FrameDeny: true})
	router.Handle("/login", security.Handler(http.HandlerFunc(login)))
	router.Handle("/search", http.HandlerFunc(search))
	router.Handle("/friends/add/{person}", http.HandlerFunc(addFriend)).Methods("GET")
}

func login(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	person := findPerson(username)
	if person == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}
	session, _ := store.Get(r, "fixture")
	session.Values["authenticated"] = true
	session.Values["username"] = person.Name
	session.Save(r, w)
}

func search(w http.ResponseWriter, r *http.Request) {
	search := r.FormValue("search")
	view := View{Search: search}
	tmpl, _ := template.ParseFiles("templates/search.html")
	tmpl.Execute(w, view)
}

func addFriend(w http.ResponseWriter, r *http.Request) {}

func findPerson(name string) *Person { return &Person{Name: name} }
