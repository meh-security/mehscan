import { UserModel } from '../model'

export function generatedApi (app: any, finale: any) {
  app.post('/api/Users', validateRegistration())
  const autoModels = [
    { name: 'User', exclude: ['password'], model: UserModel }
  ]
  for (const { name, exclude, model } of autoModels) {
    finale.resource({
      model,
      endpoints: [`/api/${name}s`, `/api/${name}s/:id`],
      excludeAttributes: exclude
    })
  }
}
