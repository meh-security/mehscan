export function direct(req: any, child_process: any) {
  return child_process.exec(req.query.direct)
}

export function propagated(req: any, child_process: any) {
  const command = req.query.propagated
  const alias = command
  return child_process.exec(alias)
}

export function separated(req: any, child_process: any) {
  return child_process.spawnSync('tool', [req.query.argument])
}
