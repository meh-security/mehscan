import { NextResponse } from "next/server"
import { getById, updateRow } from "@/lib/db"
import { canTransitionOrder } from "@/lib/order-policy"

export async function PATCH(request: Request) {
  const { orderId, status } = await request.json()
  const order = await getById("orders", orderId)
  if (!canTransitionOrder(order.status, status)) {
    return NextResponse.json({ error: "invalid transition" }, { status: 409 })
  }
  await updateRow("orders", orderId, { status })
  return NextResponse.json({ ok: true })
}
