import fs from 'node:fs'
import path from 'node:path'

export function direct(req: any, content: any) {
  return fs.writeFileSync(req.file.originalname, content)
}

export function propagated(req: any, content: any) {
  const requested = req.file.originalname
  const alias = requested
  return fs.writeFileSync(alias, content)
}

export function canonicalized(req: any, content: any) {
  const destination = path.resolve(req.file.originalname)
  return fs.writeFileSync(destination, content)
}

export function validBasename(filename: string) {
  return path.basename(filename) === filename
}
