function review(models, query) {
  return models.sequelize.query(query);
}
