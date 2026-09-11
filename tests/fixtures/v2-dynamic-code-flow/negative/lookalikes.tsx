function Execute(props: { req: any; evaluator: any }) {
  return <pre>{props.evaluator.execute(props.req.body.code)}</pre>
}
