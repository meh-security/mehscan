function Lookalikes({ user, handler }: Props) {
  app.fetch("/admin", handler);
  cache.get("/admin", handler);
  passport.verify("jwt");
  acl.canAccess(user, "admin", "read");
  return <div />;
}
