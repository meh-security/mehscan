function parse(req, customYaml) {
  return customYaml.load(req.body.payload, { schema: customYaml.JSON_SCHEMA })
}
