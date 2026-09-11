function direct(req, yaml) {
  return yaml.load(req.body.payload)
}

function propagated(req, yaml) {
  const serialized = req.body.payload
  const alias = serialized
  return yaml.load(alias)
}

function restricted(req, yaml) {
  return yaml.load(req.body.restricted, { schema: yaml.JSON_SCHEMA })
}
