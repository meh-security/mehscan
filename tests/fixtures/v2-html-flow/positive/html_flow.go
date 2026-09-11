package htmlflow

func direct(r *Request) {
	_ = template.HTML(r.FormValue("direct"))
}

func propagated(r *Request) {
	content := r.FormValue("propagated")
	alias := content
	_ = template.HTML(alias)
}

func encoded(r *Request) {
	content := html.EscapeString(r.FormValue("encoded"))
	_ = template.HTML(content)
}
