import { NextResponse, type NextRequest } from "next/server"

export function middleware(request: NextRequest) {
  if (request.nextUrl.pathname.startsWith("/dashboard")) {
    if (!request.cookies.get("auth_token")) {
      return NextResponse.redirect(new URL("/login", request.url))
    }
  }
  return NextResponse.next()
}

export const config = { matcher: ["/dashboard/:path*", "/api/:path*"] }
