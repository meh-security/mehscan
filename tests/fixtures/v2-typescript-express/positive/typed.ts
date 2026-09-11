import type { Request as ExpressRequest } from "express"

type ApiRequest = ExpressRequest
interface AdminRequest extends ApiRequest {
  principal: string
}

export function renamed(request: AdminRequest) {
  return eval(request.body.code)
}

export function parameterDestructure(
  { body: payload, query: filters, params: { id } }: ExpressRequest,
) {
  eval(payload.code)
  eval(filters.expression)
  return eval(id)
}

export function localDestructure(input: ApiRequest) {
  const { body: payload, headers } = input
  eval(payload.expression)
  return eval(headers["x-expression"] as string)
}

export function uploaded(input: ExpressRequest) {
  return consume(input.file.buffer)
}

declare function consume(value: Buffer): unknown
