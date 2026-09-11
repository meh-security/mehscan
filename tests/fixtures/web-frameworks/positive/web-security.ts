function configure(user: User, handler: Handler) {
  app.get("/admin", handler);
  passport.authenticate("jwt");
  acl.isAllowed(user, "admin", "read");
}
