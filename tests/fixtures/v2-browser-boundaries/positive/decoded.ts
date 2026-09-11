import { jwtDecode as decode } from 'jwt-decode'

export function showStoredClaim () {
  const target = document.querySelector('#claim')
  const token = localStorage.getItem('token')
  let payload: any = {}
  payload = decode(token)
  target!.innerHTML = payload.profile.biography
}
