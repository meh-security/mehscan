function direct(req: any, child_process: any) {
  return child_process.exec(req.query.direct)
}

function propagated(req: any, child_process: any) {
  const command = req.query.propagated
  const alias = command
  return child_process.exec(alias)
}

function separated(req: any, child_process: any) {
  return child_process.spawn('tool', [req.query.argument])
}
