import { NextResponse } from "next/server"
import { updateRow } from "@/lib/db"

export async function PATCH(request: Request) {
  const { userId, role } = await request.json()
  await updateRow("profiles", userId, { role, is_admin: role === "admin" })
  return NextResponse.json({ ok: true })
}
