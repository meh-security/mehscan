import { app as functions, type HttpRequest as AzureRequest } from '@azure/functions'

async function namedHandler (request: AzureRequest) {
  return { body: eval(request.query.get('code') ?? '') }
}

functions.http('danger', {
  methods: ['POST'],
  authLevel: 'anonymous',
  route: 'danger/{id}',
  handler: namedHandler
})

functions.http('privateDanger', {
  methods: ['PUT'],
  authLevel: 'function',
  route: 'private',
  handler: async (incoming) => {
    return { body: eval(await incoming.text()) }
  }
})
