import { jwtDecode } from './jwt-decode-lookalike'

export function showLocalValue () {
  const target = document.querySelector('#claim')
  const token = localStorage.getItem('token')
  const payload: any = jwtDecode(token)
  target!.innerHTML = payload.profile.biography
}
