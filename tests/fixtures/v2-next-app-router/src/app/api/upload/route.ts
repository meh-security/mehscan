import { NextResponse } from "next/server"
import { writeFile } from "fs/promises"
import path from "path"

export async function POST(request: Request) {
  const formData = await request.formData()
  const file = formData.get("file") as File
  const filename = file.name
  await writeFile(path.join(process.cwd(), "public", "uploads", filename), Buffer.from(await file.arrayBuffer()))
  return NextResponse.json({ filename })
}
