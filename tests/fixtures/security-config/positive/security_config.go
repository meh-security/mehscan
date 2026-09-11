package fixture

func review(payload io.Reader, key []byte) {
	_ = tls.Config{InsecureSkipVerify: false}
	_ = http.Cookie{Secure: false}
	_ = http.Cookie{HttpOnly: false}
	hmac.New(md5.New, key)
	var target any
	_ = gob.NewDecoder(payload).Decode(&target)
}
