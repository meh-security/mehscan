package fixture

func configure(user string, handler localhttp.HandlerFunc, accounts localgin.Accounts) {
	localhttp.Register("/admin", handler)
	localgin.BasicLogin(accounts)
	enforcer.Check(user, "admin", "read")
}
