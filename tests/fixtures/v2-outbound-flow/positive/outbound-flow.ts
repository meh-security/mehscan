function direct(req: any) {
  return fetch(req.query.direct)
}

function propagated(req: any) {
  const requested = req.query.propagated
  const alias = requested
  return fetch(alias)
}

function parsed(req: any) {
  const destination = new URL(req.query.parsed)
  return fetch(destination)
}

function validScheme(destination: URL) {
  return destination.protocol === "https:"
}

async function nestedConditional(req: any, enabled: boolean, loggedIn: boolean) {
  if (enabled) {
    const url = req.body.imageUrl
    if (loggedIn) {
      try {
        await fetch(url)
      } catch (error) {
        console.warn(error)
      }
    }
  }
}
