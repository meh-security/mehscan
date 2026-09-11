function Parse(props: { req: any; customYaml: any }) {
  return <pre>{props.customYaml.load(props.req.body.payload)}</pre>
}
