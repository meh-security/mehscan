import { NextResponse } from "next/server"
import { getById } from "@/lib/db"

export async function GET(
  _request: Request,
  { params }: { params: { id: string } },
) {
  return NextResponse.json(await getById("items", params.id))
}
