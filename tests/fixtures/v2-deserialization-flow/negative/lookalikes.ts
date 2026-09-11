function parse(req: any, customYaml: any) {
  return customYaml.load(req.body.payload, { schema: customYaml.JSON_SCHEMA })
}
