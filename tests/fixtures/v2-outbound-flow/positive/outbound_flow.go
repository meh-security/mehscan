package outboundflow

func direct(r *Request) {
	_, _ = http.Get(r.FormValue("direct"))
}

func propagated(r *Request) {
	requested := r.FormValue("propagated")
	alias := requested
	_, _ = http.Get(alias)
}

func parsed(r *Request) {
	destination, _ := url.Parse(r.FormValue("parsed"))
	_, _ = http.Get(destination.String())
}

func validScheme(destination *url.URL) bool {
	return destination.Scheme == "https"
}
