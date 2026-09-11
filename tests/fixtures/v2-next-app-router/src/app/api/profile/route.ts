import { NextResponse } from "next/server"
import { getUserFromRequest } from "@/lib/auth"
import { updateRow } from "@/lib/db"

export async function PATCH(request: Request) {
  const user = getUserFromRequest(request)
  if (!user) return NextResponse.json({ error: "unauthorized" }, { status: 401 })
  const body = await request.json()
  await updateRow("profiles", user.userId, body)
  return NextResponse.json({ ok: true })
}
