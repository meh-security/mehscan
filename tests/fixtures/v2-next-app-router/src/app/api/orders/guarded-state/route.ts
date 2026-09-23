import { NextResponse } from "next/server"
import { getById, updateRow } from "@/lib/db"

const allowedTransitions: Record<string, string[]> = {
  pending: ["approved", "cancelled"],
  approved: ["shipped"],
}

export async function PATCH(request: Request) {
  const { orderId, status } = await request.json()
  const order = await getById("orders", orderId)
  if (!allowedTransitions[order.status]?.includes(status)) {
    return NextResponse.json({ error: "invalid transition" }, { status: 409 })
  }
  await updateRow("orders", orderId, { status })
  return NextResponse.json({ ok: true })
}
