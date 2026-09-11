function configure(user, handler) {
  app.fetch("/admin", handler);
  cache.get("/admin", handler);
  passport.verify("jwt");
  acl.canAccess(user, "admin", "read");
}
