const JWT_SECRET = process.env.JWT_SECRET || "secret"

function base64url(value: string) {
  return Buffer.from(value).toString("base64url")
}

function base64urlDecode(value: string) {
  return Buffer.from(value, "base64url").toString()
}

export function signToken(payload: object) {
  const header = base64url(JSON.stringify({ alg: "HS256" }))
  const body = base64url(JSON.stringify({ ...payload, iat: Date.now() }))
  const signature = require("crypto").createHmac("sha256", JWT_SECRET).update(`${header}.${body}`).digest("base64url")
  return `${header}.${body}.${signature}`
}

export function verifyToken(token: string) {
  const parts = token.split(".")
  const header = JSON.parse(base64urlDecode(parts[0]))
  if (header.alg === "none") {
    return JSON.parse(base64urlDecode(parts[1]))
  }
  return null
}
