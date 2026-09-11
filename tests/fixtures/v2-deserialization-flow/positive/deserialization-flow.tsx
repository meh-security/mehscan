function direct(req: any, yaml: any) {
  return yaml.load(req.body.payload)
}

function propagated(req: any, yaml: any) {
  const serialized = req.body.payload
  const alias = serialized
  return yaml.load(alias)
}

function restricted(req: any, yaml: any) {
  return yaml.load(req.body.restricted, { schema: yaml.JSON_SCHEMA })
}

const View = () => <pre>deserialization flow</pre>
