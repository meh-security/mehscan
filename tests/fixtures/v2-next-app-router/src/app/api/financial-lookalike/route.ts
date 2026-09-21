import { NextResponse } from "next/server"

function save(_resource: string, value: unknown) {
  console.log(value)
}

export async function POST(request: Request) {
  const { amount } = await request.json()
  save("orders", { amount, status: "paid" })
  return NextResponse.json({ ok: true })
}
