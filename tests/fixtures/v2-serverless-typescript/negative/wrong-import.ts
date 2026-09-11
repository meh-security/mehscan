import type { APIGatewayProxyEvent } from './aws-lambda-lookalike'

export function handler (event: APIGatewayProxyEvent) {
  return eval(event.body)
}
