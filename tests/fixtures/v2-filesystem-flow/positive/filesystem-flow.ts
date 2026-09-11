function direct(req: any, fs: any) {
  return fs.readFileSync(req.query.direct)
}

function propagated(req: any, fs: any, content: any) {
  const requested = req.query.propagated
  const alias = requested
  return fs.writeFileSync(alias, content)
}

function canonicalized(req: any, fs: any, path: any) {
  const canonical = path.resolve(req.query.protected)
  return fs.readFileSync(canonical)
}

function contained(candidate: string, root: string, path: any) {
  return !path.relative(root, candidate).startsWith("..")
}

function renderLayout(req: any, res: any, path: any, enabled: boolean) {
  if (enabled) {
    void req.body.layout
    path.resolve(req.body.layout)
    res.render("result", {
      ...req.body
    })
  }
}
