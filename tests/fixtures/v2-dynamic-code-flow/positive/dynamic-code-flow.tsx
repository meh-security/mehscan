function direct(req: any) {
  return eval(req.body.code)
}

function propagated(req: any) {
  const code = req.body.code
  const alias = code
  return eval(alias)
}

function restricted(req: any, vm: any) {
  return vm.runInNewContext(req.body.restricted, Object.create(null))
}

const View = () => <pre>dynamic code flow</pre>
