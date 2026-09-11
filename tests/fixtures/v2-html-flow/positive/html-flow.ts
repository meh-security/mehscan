function direct(req: any, res: any) {
  return res.send(req.query.direct)
}

function propagated(req: any, res: any) {
  const content = req.query.propagated
  const alias = content
  return res.send(alias)
}

function encoded(req: any, res: any, he: any) {
  const content = he.encode(req.query.encoded)
  return res.send(content)
}

function getSubsFromFile () {
  const subtitles = config.get<string>('application.promotion.subtitles') ?? 'owasp_promo.vtt'
  const data = fs.readFileSync('frontend/dist/frontend/assets/public/videos/' + subtitles, 'utf8')
  return data.toString()
}

function storedSubtitle(res: any) {
  const subs = getSubsFromFile()
  let compiledTemplate = '<script id="subtitle"></script>'
  compiledTemplate = compiledTemplate.replace('<script id="subtitle"></script>', '<script id="subtitle" type="text/vtt" data-label="English">' + subs + '</script>')
  return res.send(compiledTemplate)
}
