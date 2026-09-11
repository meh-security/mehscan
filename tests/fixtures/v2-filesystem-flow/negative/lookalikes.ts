function run(custom: any, value: string) {
  return custom.resolve(value)
}

function mutuallyExclusiveRender(req: any, res: any, useLayout: boolean) {
  if (useLayout) {
    void req.body.layout
  } else {
    res.render("result", {
      ...req.body
    })
  }
}

function fixedRender(res: any, locals: any) {
  res.render("result", {
    ...locals
  })
}
