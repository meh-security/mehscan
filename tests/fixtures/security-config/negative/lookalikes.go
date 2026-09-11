package fixture

func review(payload io.Reader, key []byte) {
	_ = localtls.Config{VerifyPeer: false}
	_ = localhttp.Cookie{TransportSecure: false}
	_ = localhttp.Cookie{BlockScript: false}
	hashFactory.New(md5.New, key)
	safegob.NewDecoder(payload)
}
