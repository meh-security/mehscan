function run(helper: any, destination: string, base: string) {
  return helper.sameOrigin(destination, base)
}

function mutuallyExclusive(req: any, res: any, useRequest: boolean) {
  let destination = "/safe"
  if (useRequest) {
    destination = req.query.to
  } else {
    return res.redirect(destination)
  }
}
