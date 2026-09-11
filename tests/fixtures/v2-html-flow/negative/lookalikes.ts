function encode(he: any, value: string) {
  return he.encodeUrl(value)
}

function getSubsFromFile () {
  const subtitles = config.get<string>('application.promotion.subtitles') ?? 'owasp_promo.vtt'
  const data = fs.readFileSync('frontend/dist/frontend/assets/public/videos/' + subtitles, 'utf8')
  return data.toString()
}

function mutuallyExclusiveSubtitle(res: any, useSubtitle: boolean) {
  let subs = ''
  let compiledTemplate = '<script id="subtitle"></script>'
  if (useSubtitle) {
    subs = getSubsFromFile()
  } else {
    compiledTemplate = compiledTemplate.replace('<script id="subtitle"></script>', '<script id="subtitle" type="text/vtt" data-label="English">' + subs + '</script>')
  }
  return res.send(compiledTemplate)
}
