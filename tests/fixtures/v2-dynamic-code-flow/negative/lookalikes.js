function execute(req, evaluator) {
  return evaluator.execute(req.body.code)
}
