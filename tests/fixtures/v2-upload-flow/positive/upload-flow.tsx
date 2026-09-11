export function direct(req: any, fs: any, content: any) {
  return fs.writeFileSync(req.file.originalname, content)
}

export function propagated(req: any, fs: any, content: any) {
  const requested = req.file.originalname
  const alias = requested
  return fs.writeFileSync(alias, content)
}

export function canonicalized(req: any, fs: any, path: any, content: any) {
  const destination = path.resolve(req.file.originalname)
  return fs.writeFileSync(destination, content)
}

export function validBasename(filename: string, path: any) {
  return path.basename(filename) === filename
}
