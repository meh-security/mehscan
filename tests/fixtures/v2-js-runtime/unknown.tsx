export function renderedSomewhere(req: any) {
  return <p>{String(fetch(req.query.url))}</p>
}
