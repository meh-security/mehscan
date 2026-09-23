'use client'

import { apiConfig, requestRoutes } from '../services/browser-api'

export function fixedBrowserRequest (token: string, userId: string) {
  const requestUrl = apiConfig.identityService + requestRoutes.user
  return fetch(requestUrl.replace('<userId>', userId), {
    headers: { Authorization: `Bearer ${token}` }
  })
}

export function* fixedGeneratorBrowserRequest (token: string) {
  const generatorUrl = apiConfig.identityService + requestRoutes.user
  yield fetch(generatorUrl, {
    headers: { Authorization: `Bearer ${token}` }
  })
}

export function* fixedMultilineBrowserRequest (token: string, userId: string) {
  const multilineUrl =
    apiConfig.identityService +
    requestRoutes.user.replace('<userId>', userId)
  yield fetch(multilineUrl, {
    headers: { Authorization: `Bearer ${token}` }
  })
}

export function* fixedDynamicSuffixRequest (token: string, userId: string) {
  const suffixUrl = apiConfig.identityService + requestRoutes.user + '?selected=' + userId
  yield fetch(suffixUrl, {
    headers: { Authorization: `Bearer ${token}` }
  })
}

export function externalBrowserRequest (token: string) {
  const externalUrl = apiConfig.externalService + requestRoutes.user
  return fetch(externalUrl, {
    headers: { Authorization: `Bearer ${token}` }
  })
}

export function replacedAuthorityRequest (token: string, destination: string) {
  const replaceableUrl = requestRoutes.replaceableAuthority
  return fetch(replaceableUrl.replace('<host>', destination), {
    headers: { Authorization: `Bearer ${token}` }
  })
}

export function dynamicBrowserRequest (token: string, destination: string) {
  return fetch(destination, {
    headers: { Authorization: `Bearer ${token}` }
  })
}
