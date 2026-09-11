import fs from 'node:fs'
import path from 'node:path'
import { pipeline } from 'node:stream/promises'

export async function extract (directory: any) {
  const root = path.resolve('uploads') + path.sep
  for (const entry of directory.files) {
    const fileName = entry.path
    const absolutePath = path.resolve(root, fileName)
    if (absolutePath.startsWith(root)) {
      await pipeline(entry.stream(), fs.createWriteStream(absolutePath))
    }
  }
}
