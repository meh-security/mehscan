import Fastify from 'fastify'

const app = Fastify()

app.get(
  '/echo',
  {
    schema: {
      querystring: {
        type: 'object',
        additionalProperties: false,
        properties: { value: { type: 'string', maxLength: 80 } }
      }
    }
  },
  async (request, reply) => {
    reply.type('text/plain')
    return reply.send(request.query.value)
  }
)
