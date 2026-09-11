function Review({ models, query }: any) {
  models.sequelize.query(query);
  return <div>done</div>;
}
