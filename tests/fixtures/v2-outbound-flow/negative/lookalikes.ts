function run(parser: any, value: string) {
  return parser.URL(value)
}

function mutuallyExclusive(req: any, useRequest: boolean) {
  let url = "https://example.invalid/image.png"
  if (useRequest) {
    url = req.body.imageUrl
  } else {
    return fetch(url)
  }
}
