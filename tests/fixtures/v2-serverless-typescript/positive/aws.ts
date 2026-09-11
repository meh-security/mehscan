import type {
  APIGatewayProxyEvent as ApiEvent,
  APIGatewayProxyHandler as ApiHandler
} from 'aws-lambda'

interface ExtendedEvent extends ApiEvent {}

export async function direct ({ body }: ExtendedEvent) {
  return eval(body ?? '')
}

export const handler: ApiHandler = async (incoming) => {
  return eval(incoming.queryStringParameters?.code ?? '')
}
