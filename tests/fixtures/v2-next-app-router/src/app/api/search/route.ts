import { NextResponse } from "next/server"
import { query } from "@/lib/db"

export async function POST(request: Request) {
  const { term } = await request.json()
  const rows = await query("items", `name ILIKE '%${term}%'`)
  return NextResponse.json(rows)
}
