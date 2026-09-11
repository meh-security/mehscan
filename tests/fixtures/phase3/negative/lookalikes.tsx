export function Review(props: { value: string }) {
  database.safeQuery(props.value);
  local.fetch(props.value);
  filesystem.safeRead(props.value);
  sandbox.safeEval(props.value);
  return <span>Safe</span>;
}

