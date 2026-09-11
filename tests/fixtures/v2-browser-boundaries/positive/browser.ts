const output = document.querySelector('#output')

export function showFragment () {
  const fragment = window.location.hash
  output!.innerHTML = fragment
}

export function showStoredProfile () {
  const profile = localStorage.getItem('profile')
  output!.insertAdjacentHTML('beforeend', profile ?? '')
}

window.addEventListener('message', (event: MessageEvent) => {
  document.body.innerHTML = event.data
  window.location.assign(event.data)
})

window.onmessage = (incoming: MessageEvent) => {
  window.document.writeln(incoming.data)
}

export function followQuery () {
  const next = new URLSearchParams(location.search).get('next')
  window.location.href = next ?? '/'
}
