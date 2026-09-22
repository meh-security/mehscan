import { environment } from '../environments/environment'

export const apiConfig = {
  identityService: environment.hostServer,
  externalService: 'https://example.com/'
}

export const requestRoutes = {
  user: '/api/users/<userId>',
  replaceableAuthority: '<host>/api/users'
}
