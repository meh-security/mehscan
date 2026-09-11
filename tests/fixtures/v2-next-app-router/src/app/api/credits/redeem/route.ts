import { NextResponse } from "next/server"
import { query, updateRow } from "@/lib/db"

export async function POST(request: Request) {
  const { amount } = await request.json()
  const credits = await query("credits", "user_id = 'known'")
  const currentBalance = credits[0].balance
  if (currentBalance < amount) return NextResponse.json({ error: "funds" }, { status: 400 })
  const newBalance = currentBalance - amount
  await updateRow("credits", credits[0].id, { balance: newBalance })
  return NextResponse.json({ newBalance })
}
