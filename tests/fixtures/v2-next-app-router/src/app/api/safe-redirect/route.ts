import { NextResponse } from "next/server"

export function GET(request: Request) {
  const destination = new URL(request.url).searchParams.get("next") || "/"
  try {
    const url = new URL(destination, request.url)
    if (url.origin !== new URL(request.url).origin) throw new Error("external")
    return NextResponse.redirect(url)
  } catch {
    return NextResponse.redirect(new URL("/", request.url))
  }
}
