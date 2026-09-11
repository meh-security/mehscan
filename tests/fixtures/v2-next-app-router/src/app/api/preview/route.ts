import { NextResponse } from "next/server"

export async function POST(request: Request) {
  const { html } = await request.json()
  return new Response(html, {
    headers: { "Content-Type": "text/html; charset=utf-8" },
  })
}

export async function PUT(request: Request) {
  const { destination } = await request.json()
  return NextResponse.redirect(destination)
}
