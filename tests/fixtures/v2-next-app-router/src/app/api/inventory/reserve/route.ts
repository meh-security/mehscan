import { NextResponse } from "next/server"
import { query, updateRow } from "@/lib/db"

export async function POST(request: Request) {
  const body = await request.json()
  const requested = body.quantity
  const rows = await query("inventory", "sku = 'known'")
  const available = rows[0]["stock"]
  if (requested > available) {
    return NextResponse.json({ error: "unavailable" }, { status: 409 })
  }
  const remaining = available - requested
  await updateRow("inventory", rows[0].id, { stock: remaining })
  return NextResponse.json({ remaining })
}
