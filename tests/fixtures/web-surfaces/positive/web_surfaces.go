package fixture

func review(html string, location string, writer http.ResponseWriter, request *http.Request) {
	_ = template.HTML(html)
	http.Redirect(writer, request, location, 302)
	request.FormFile("upload")
}
