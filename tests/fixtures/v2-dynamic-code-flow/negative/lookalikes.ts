function execute(req: any, evaluator: any) {
  return evaluator.execute(req.body.code)
}
