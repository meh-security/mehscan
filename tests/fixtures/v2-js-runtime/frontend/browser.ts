document.title = "browser runtime"

export function loadPreview(req: any) {
  return fetch(req.query.url)
}
