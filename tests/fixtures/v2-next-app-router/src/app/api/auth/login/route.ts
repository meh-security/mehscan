import { NextResponse } from "next/server"

export async function POST(request: Request) {
  const { email, password } = await request.json()
  if (email === "missing@example.test") {
    return NextResponse.json({ error: "No account found" }, { status: 404 })
  }
  if (email === "admin@example.test" && password === "admin") {
    return NextResponse.json({ token: "privileged" })
  }
  if (password !== "known-password") {
    return NextResponse.json({ error: "Invalid password" }, { status: 401 })
  }
  return NextResponse.json({ token: "ordinary" })
}
