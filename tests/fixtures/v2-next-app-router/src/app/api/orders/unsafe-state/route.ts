import { NextResponse } from "next/server"
import { updateRow } from "@/lib/db"

export async function PATCH(request: Request) {
  const { orderId, status } = await request.json()
  await updateRow("orders", orderId, { status })
  return NextResponse.json({ ok: true })
}
