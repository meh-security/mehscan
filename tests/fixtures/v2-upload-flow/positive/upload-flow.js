function direct(req, fs, content) {
  return fs.writeFileSync(req.file.originalname, content)
}

function propagated(req, fs, content) {
  const requested = req.file.originalname
  const alias = requested
  return fs.writeFileSync(alias, content)
}

function canonicalized(req, fs, path, content) {
  const destination = path.resolve(req.file.originalname)
  return fs.writeFileSync(destination, content)
}

function validBasename(filename, path) {
  return path.basename(filename) === filename
}
