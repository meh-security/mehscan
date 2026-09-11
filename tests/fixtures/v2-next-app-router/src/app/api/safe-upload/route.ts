import { NextResponse } from "next/server"
import { writeFile } from "fs/promises"
import path from "path"

export async function POST(request: Request) {
  const formData = await request.formData()
  const file = formData.get("file") as File
  const filename = `${crypto.randomUUID()}.bin`
  await writeFile(path.join(process.cwd(), "private", filename), Buffer.from(await file.arrayBuffer()))
  return NextResponse.json({ stored: true })
}
