package deserializationflow

func direct(r *http.Request) error {
	var target any
	return gob.NewDecoder(strings.NewReader(r.FormValue("payload"))).Decode(&target)
}

func propagated(r *http.Request) error {
	serialized := r.FormValue("payload")
	alias := serialized
	var target any
	return gob.NewDecoder(strings.NewReader(alias)).Decode(&target)
}

func restricted(r *http.Request) error {
	return json.Unmarshal([]byte(r.FormValue("restricted")), &UploadDTO{})
}
