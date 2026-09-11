import { NextResponse } from "next/server"
import { depthLimit } from "graphql-depth-limit"

export async function POST(request: Request) {
  const { query } = await request.json()
  depthLimit(8)(query)
  return NextResponse.json({ data: {} })
}
