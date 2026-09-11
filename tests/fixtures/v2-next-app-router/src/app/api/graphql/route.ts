import { NextResponse } from "next/server"

export async function POST(request: Request) {
  const { query } = await request.json()
  if (query.includes("__schema")) {
    return NextResponse.json({ data: { __schema: {} } })
  }
  return NextResponse.json({ data: {} })
}
