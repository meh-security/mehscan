import { NextResponse } from "next/server"
import { rateLimit } from "@/lib/rate-limit"

export async function POST(request: Request) {
  await rateLimit(request)
  await sendResetEmail(await request.json())
  return NextResponse.json({ message: "If the account exists, email was sent" })
}

declare function sendResetEmail(body: unknown): Promise<void>
