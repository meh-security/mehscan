export function Review(props: {
  query: string;
  url: string;
  path: string;
  code: string;
}) {
  sequelize.query(props.query);
  fetch(props.url);
  fs.readFileSync(props.path);
  fs.writeFileSync(props.path, "content");
  eval(props.code);
  return <button>Review</button>;
}

