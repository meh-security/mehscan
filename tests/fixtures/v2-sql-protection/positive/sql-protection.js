function review(models, query, email) {
  return models.sequelize.query(query, { bind: [email], type: "select" });
}
