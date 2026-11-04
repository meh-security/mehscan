import fs from 'node:fs'
import path from 'node:path'

function direct(req, content) {
  return fs.writeFileSync(req.file.originalname, content)
}

function propagated(req, content) {
  const requested = req.file.originalname
  const alias = requested
  return fs.writeFileSync(alias, content)
}

function canonicalized(req, content) {
  const destination = path.resolve(req.file.originalname)
  return fs.writeFileSync(destination, content)
}

function validBasename(filename) {
  return path.basename(filename) === filename
}
