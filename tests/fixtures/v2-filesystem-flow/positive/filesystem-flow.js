function direct(req, fs) {
  return fs.readFileSync(req.query.direct)
}

function propagated(req, fs, content) {
  const requested = req.query.propagated
  const alias = requested
  return fs.writeFileSync(alias, content)
}

function canonicalized(req, fs, path) {
  const canonical = path.resolve(req.query.protected)
  return fs.readFileSync(canonical)
}

function contained(candidate, root, path) {
  return !path.relative(root, candidate).startsWith("..")
}
