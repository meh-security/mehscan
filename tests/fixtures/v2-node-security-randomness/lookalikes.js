const Math = {
  random () {
    return 42
  }
}

export function createAuthToken () {
  const authToken = Math.random()
  return authToken
}

export function parserToken () {
  const token = globalThis.crypto.randomUUID()
  return token
}
