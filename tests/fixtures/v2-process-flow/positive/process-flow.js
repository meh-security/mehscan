function direct(req, child_process) {
  return child_process.exec(req.query.direct)
}

function propagated(req, child_process) {
  const command = req.query.propagated
  const alias = command
  return child_process.exec(alias)
}

function separated(req, child_process) {
  return child_process.execFile('tool', [req.query.argument])
}
