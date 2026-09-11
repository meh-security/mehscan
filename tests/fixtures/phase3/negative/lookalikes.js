function review(value) {
  database.safeQuery(value);
  local.fetch(value);
  filesystem.safeRead(value);
  sandbox.safeEval(value);
}

