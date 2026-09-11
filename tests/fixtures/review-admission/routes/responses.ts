import * as responseUtils from '../lib/responses'

export function directJsonResponse (res: any, value: unknown) {
  res.send({ data: value })
}

export function helperJsonResponse (res: any, value: unknown) {
  res.send(responseUtils.jsonEnvelope(value))
}

export function dynamicResponse (res: any, value: unknown) {
  res.send(responseUtils.dynamicEnvelope(value))
}

export function shadowedHelperResponse (res: any, responseUtils: any, value: unknown) {
  res.send(responseUtils.jsonEnvelope(value))
}
