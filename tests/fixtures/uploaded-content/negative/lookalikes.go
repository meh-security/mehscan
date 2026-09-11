package fixture

func review(request *http.Request) {
	stream := request.MultipartForm.File["upload"][0]
	_ = stream
}
