import { NextResponse } from "next/server"

export async function POST(request: Request) {
  const { email } = await request.json()
  const resetToken = `${email}-${crypto.randomUUID()}`
  return NextResponse.json({ token: resetToken })
}
