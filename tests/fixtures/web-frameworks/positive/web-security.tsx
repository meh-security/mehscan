function WebSecurity({ user, handler }: Props) {
  app.get("/admin", handler);
  passport.authenticate("jwt");
  acl.isAllowed(user, "admin", "read");
  return <div />;
}
