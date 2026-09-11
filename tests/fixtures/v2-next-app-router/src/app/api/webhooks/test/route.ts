import { NextResponse } from "next/server"

export async function POST(request: Request) {
  const { webhook_url } = await request.json()
  try {
    await fetch(webhook_url, { method: "POST" })
  } catch {}
  return NextResponse.json({ sent: true })
}
