package fixture

func review(request *http.Request) {
	stream, _ := request.MultipartForm.File["upload"][0].Open()
	_ = stream
}
