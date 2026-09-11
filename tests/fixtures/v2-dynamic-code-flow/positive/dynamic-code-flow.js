function direct(req) {
  return eval(req.body.code)
}

function propagated(req) {
  const code = req.body.code
  const alias = code
  return eval(alias)
}

function restricted(req, vm) {
  return vm.runInNewContext(req.body.restricted, Object.create(null))
}
