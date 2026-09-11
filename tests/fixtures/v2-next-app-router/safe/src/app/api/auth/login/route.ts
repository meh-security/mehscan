import { NextResponse } from "next/server"
import { rateLimit } from "@/lib/rate-limit"

export async function POST(request: Request) {
  await rateLimit(request)
  const { email, password } = await request.json()
  const valid = await verifyCredential(email, password)
  if (!valid) return NextResponse.json({ error: "Invalid credentials" }, { status: 401 })
  return NextResponse.json({ token: "server-generated" })
}

declare function verifyCredential(email: string, password: string): Promise<boolean>
