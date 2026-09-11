import { NextResponse } from "next/server"

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url)
  const url = searchParams.get("url")
  if (!url) return NextResponse.json({ error: "missing" }, { status: 400 })

  try {
    return NextResponse.json({ body: await (await fetch(url)).text() })
  } catch {
    return NextResponse.json({ error: "failed" }, { status: 500 })
  }
}
