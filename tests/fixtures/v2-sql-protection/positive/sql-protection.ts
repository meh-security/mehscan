function review(models: any, query: string, criteria: string) {
  return models.sequelize.query(query, { replacements: { criteria } });
}
