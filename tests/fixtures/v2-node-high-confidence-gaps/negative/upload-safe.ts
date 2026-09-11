import type { Request } from 'express'
import { parseXmlSafely } from './xml-safe'

export async function upload ({ file }: Request) {
  return await parseXmlSafely(file.buffer.toString())
}
