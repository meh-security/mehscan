package fixture

import "net/http"

func review(r *http.Request) {
	body := r.FormValue("email")
	query := r.URL.Query().Get("q")
	path := r.PathValue("id")
	header := r.Header.Get("X-Trace")
	cookie, _ := r.Cookie("session")
	_, _, _, _, _ = body, query, path, header, cookie
}
