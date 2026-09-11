import { app, type HttpRequest } from '@azure/functions'

function helper (request: HttpRequest) {
  return eval(request.query.get('code'))
}

export const unrelated = app.storageQueue
void helper
