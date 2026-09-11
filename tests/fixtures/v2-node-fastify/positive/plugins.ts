import { FastifyInstance } from 'fastify'
import helmet from '@fastify/helmet'
import cors from '@fastify/cors'
import multipart from '@fastify/multipart'

export async function protections(fastify: FastifyInstance) {
  await fastify.register(helmet)
  await fastify.register(cors, { origin: ['https://example.test'] })
  await fastify.register(multipart, { limits: { fileSize: 1024 } })
  fastify.addHook('onRequest', async (request, reply) => {
    if (!request.session.user) reply.unauthorized()
  })
}
