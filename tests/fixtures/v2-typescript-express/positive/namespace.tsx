import type * as express from "express"

export function ExpressionPreview({ query: filters }: express.Request) {
  return <pre>{String(eval(filters.expression))}</pre>
}
