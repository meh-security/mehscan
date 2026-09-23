import { NextResponse } from "next/server"
import { insertRow } from "@/lib/db"
import { lookupPrice } from "@/lib/pricing"

export async function POST(request: Request) {
  const { plan, submittedPrice } = await request.json()
  const expectedPrice = await lookupPrice(plan)
  await insertRow("orders", {
    plan,
    amount: submittedPrice,
    status: "paid"
  })
  return NextResponse.json({ ok: true, expectedPrice })
}
