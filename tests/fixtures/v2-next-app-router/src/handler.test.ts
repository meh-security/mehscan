import { NextResponse } from "next/server"

export async function POST(request: Request) {
  const { url } = await request.json()
  await fetch(url)
  return NextResponse.json({ ok: true })
}
