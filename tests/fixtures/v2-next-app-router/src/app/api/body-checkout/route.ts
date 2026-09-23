import { NextResponse } from "next/server"
import { insertRow } from "@/lib/db"

export async function POST(request: Request) {
  const body = await request.json()
  const submittedTotal = body.total
  await insertRow("payments", {
    amount: submittedTotal,
    status: "completed"
  })
  return NextResponse.json({ ok: true })
}
