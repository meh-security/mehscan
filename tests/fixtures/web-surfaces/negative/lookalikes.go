package fixture

func review(html string, location string, writer localhttp.ResponseWriter, request *localhttp.Request) {
	_ = safeTemplate.HTML(html)
	localhttp.Redirect(writer, request, location, 302)
	request.LocalFile("upload")
}
