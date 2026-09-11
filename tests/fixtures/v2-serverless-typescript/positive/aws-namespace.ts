import type * as Lambda from 'aws-lambda'

export function namespaceHandler (event: Lambda.APIGatewayProxyEvent) {
  return eval(event.body ?? '')
}
