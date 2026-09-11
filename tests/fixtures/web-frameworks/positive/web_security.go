package fixture

func configure(user string, handler http.HandlerFunc, accounts gin.Accounts) {
	http.HandleFunc("/admin", handler)
	gin.BasicAuth(accounts)
	enforcer.Enforce(user, "admin", "read")
}
