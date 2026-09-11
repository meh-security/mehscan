import type { Request } from 'express'
import { parseXmlString as parseUploadedXml } from './xml'

export async function upload ({ file }: Request) {
  const data = file.buffer.toString()
  return await parseUploadedXml(data)
}
