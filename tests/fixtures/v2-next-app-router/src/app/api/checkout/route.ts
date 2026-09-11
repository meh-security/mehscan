import { NextResponse } from "next/server"
import { insertRow } from "@/lib/db"

export async function POST(request: Request) {
  const { plan, price } = await request.json()
  await insertRow("orders", { plan, amount: price, status: "paid" })
  return NextResponse.json({ ok: true })
}
