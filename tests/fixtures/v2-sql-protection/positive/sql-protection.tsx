function Review({ sequelize, query, id }: any) {
  sequelize.query(query, { bind: [id] });
  return <div>done</div>;
}
