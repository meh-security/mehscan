function review(value: string) {
  database.safeQuery(value);
  local.fetch(value);
  filesystem.safeRead(value);
  sandbox.safeEval(value);
}

