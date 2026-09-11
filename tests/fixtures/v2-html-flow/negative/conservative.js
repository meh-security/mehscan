function reassignmentKill(req, res) {
  let content = req.query.reassigned
  content = 'fixed'
  return res.send(content)
}

function branchAssignment(req, res, enabled) {
  let content = 'fixed'
  if (enabled) {
    content = req.query.branch
  }
  return res.send(content)
}

function loopMutation(req, res, values) {
  let content = req.query.loop
  for (const value of values) {
    content = value
  }
  return res.send(content)
}

function fieldFlow(req, res) {
  this.content = req.query.field
  return res.send(this.content)
}

function sourceFunction(req) {
  const content = req.query.crossFunction
  return content
}

function sinkFunction(res) {
  const content = 'fixed'
  return res.send(content)
}

function branchSink(req, res, enabled) {
  const content = req.query.branchSink
  if (enabled) {
    return res.send(content)
  }
}

function tooManyAliases(req, res) {
  const first = req.query.deep
  const second = first
  const third = second
  const fourth = third
  const fifth = fourth
  const sixth = fifth
  return res.send(sixth)
}
