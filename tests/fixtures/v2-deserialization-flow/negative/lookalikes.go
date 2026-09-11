package deserializationflow

func parse(r *http.Request) error {
	var target UploadDTO
	return customjson.Unmarshal([]byte(r.FormValue("payload")), &target)
}
