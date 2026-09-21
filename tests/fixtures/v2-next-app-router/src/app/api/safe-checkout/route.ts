import { NextResponse } from "next/server"
import { insertRow } from "@/lib/db"

async function loadPlan(plan: string) {
  return { id: plan, price: 1200, currency: "USD" }
}

export async function POST(request: Request) {
  const { plan } = await request.json()
  const catalogPlan = await loadPlan(plan)
  await insertRow("orders", {
    plan: catalogPlan.id,
    amount: catalogPlan.price,
    status: "paid"
  })
  return NextResponse.json({ ok: true })
}
