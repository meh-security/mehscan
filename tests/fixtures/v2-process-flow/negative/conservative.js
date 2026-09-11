function reassignmentKill(req, child_process) {
  let command = req.query.reassigned
  command = 'tool'
  return child_process.exec(command)
}

function branchAssignment(req, child_process, enabled) {
  let command = 'tool'
  if (enabled) {
    command = req.query.branch
  }
  return child_process.exec(command)
}

function loopMutation(req, child_process, values) {
  let command = req.query.loop
  for (const value of values) {
    command = value
  }
  return child_process.exec(command)
}

function fieldFlow(req, child_process) {
  this.command = req.query.field
  return child_process.exec(this.command)
}

function sourceFunction(req) {
  const command = req.query.crossFunction
  return command
}

function sinkFunction(child_process) {
  const command = 'tool'
  return child_process.exec(command)
}

function branchSink(req, child_process, enabled) {
  const command = req.query.branchSink
  if (enabled) {
    return child_process.exec(command)
  }
}

function tooManyAliases(req, child_process) {
  const first = req.query.deep
  const second = first
  const third = second
  const fourth = third
  const fifth = fourth
  const sixth = fifth
  return child_process.exec(sixth)
}
