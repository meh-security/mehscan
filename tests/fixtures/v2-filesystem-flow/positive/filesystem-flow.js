import * as fs from 'node:fs'
function direct(req) {
  return fs.readFileSync(req.query.direct)
}

function propagated(req, content) {
  const requested = req.query.propagated
  const alias = requested
  return fs.writeFileSync(alias, content)
}

function canonicalized(req, path) {
  const canonical = path.resolve(req.query.protected)
  return fs.readFileSync(canonical)
}

function contained(candidate, root, path) {
  return !path.relative(root, candidate).startsWith("..")
}
