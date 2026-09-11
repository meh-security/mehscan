import fs from 'node:fs'
import path from 'node:path'
import { pipeline } from 'node:stream/promises'

export async function extract (directory: any) {
  for (const entry of directory.files) {
    const fileName = entry.path
    const absolutePath = path.resolve('uploads/' + fileName)
    if (absolutePath.includes(path.resolve('.'))) {
      await pipeline(entry.stream(), fs.createWriteStream('uploads/' + fileName))
    }
  }
}
