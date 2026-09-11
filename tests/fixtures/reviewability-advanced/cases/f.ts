export function inspect(req: any, child_process: any) {
  const executable = req.query.program
  return child_process.spawn(executable, ['--version'])
}
