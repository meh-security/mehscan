function review(req, models) {
  const body = req.body.email;
  const query = req.query.q;
  const path = req.params.id;
  const header = req.headers["x-trace"];
  const cookie = req.cookies.session;
  models.sequelize.query(query);
}
