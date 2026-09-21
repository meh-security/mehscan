import { NextResponse } from "next/server"
import postgres from "postgres"

const sql = postgres(process.env.DATABASE_URL!)

export async function POST(request: Request) {
  const { quantity } = await request.json()
  const rows = await sql`
    UPDATE inventory
    SET stock = stock - ${quantity}
    WHERE sku = 'known' AND stock >= ${quantity}
    RETURNING stock
  `
  if (rows.length === 0) {
    return NextResponse.json({ error: "unavailable" }, { status: 409 })
  }
  return NextResponse.json({ remaining: rows[0].stock })
}
