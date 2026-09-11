function review(models: any, query: string) {
  return models.sequelize.query(query);
}
