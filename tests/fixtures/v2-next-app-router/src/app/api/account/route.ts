import { NextResponse } from "next/server"
import { getUserFromRequest } from "@/lib/auth"

export function GET(request: Request) {
  const user = getUserFromRequest(request)
  if (!user) {
    return NextResponse.json({ error: "unauthorized" }, { status: 401 })
  }
  return NextResponse.json({ id: user.userId })
}
