package redirectflow

func direct(w ResponseWriter, r *Request) {
	http.Redirect(w, r, r.FormValue("direct"), 302)
}

func propagated(w ResponseWriter, r *Request) {
	requested := r.FormValue("propagated")
	alias := requested
	http.Redirect(w, r, alias, 302)
}

func parsed(w ResponseWriter, r *Request) {
	destination, _ := url.Parse(r.FormValue("parsed"))
	http.Redirect(w, r, destination.String(), 302)
}

func validLocal(destination *url.URL) bool {
	return !destination.IsAbs()
}
