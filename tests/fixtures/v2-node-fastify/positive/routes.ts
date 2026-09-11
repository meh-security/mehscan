import { FastifyInstance } from 'fastify'

export async function routes(fastify: FastifyInstance) {
  fastify.get(
    '/preview',
    {
      schema: {
        querystring: { type: 'object', properties: { html: { type: 'string' } } }
      }
    },
    async (request, reply) => {
      return reply.type('text/html').send(request.query.html)
    }
  )

  fastify.get('/leave', async (request, reply) => {
    return reply.redirect(request.query.next)
  })

  fastify.get('/run', async (request) => {
    return eval(request.query.code)
  })

  fastify.delete(
    '/admin/:id',
    { preHandler: (request, reply) => request.isAdmin(reply) },
    async (request) => ({ deleted: request.params.id })
  )
}
