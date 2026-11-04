import fs from 'node:fs'
import path from 'node:path'

function direct(req: any, content: any) {
  return fs.writeFileSync(req.file.originalname, content)
}

function propagated(req: any, content: any) {
  const requested = req.file.originalname
  const alias = requested
  return fs.writeFileSync(alias, content)
}

function canonicalized(req: any, content: any) {
  const destination = path.resolve(req.file.originalname)
  return fs.writeFileSync(destination, content)
}

function validBasename(filename: string) {
  return path.basename(filename) === filename
}
