import express from "express"

export function loadOnServer(req: any) {
  return fetch(req.query.url)
}
