function configure(user, handler) {
  app.get("/admin", handler);
  passport.authenticate("jwt");
  acl.isAllowed(user, "admin", "read");
}
