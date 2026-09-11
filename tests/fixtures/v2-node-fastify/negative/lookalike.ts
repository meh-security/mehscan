const fastify = {
  get(_path: string, handler: Function) {
    return handler({ query: { value: 'local' } }, { send: console.log })
  }
}

fastify.get('/not-fastify', (request: any, reply: any) => {
  reply.send(request.query.value)
})
