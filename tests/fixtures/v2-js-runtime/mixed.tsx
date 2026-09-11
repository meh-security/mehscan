"use client"
import { readFile } from "node:fs"

export function mixedRuntime(req: any) {
  return <p>{String(fetch(req.query.url))}{String(readFile)}</p>
}
