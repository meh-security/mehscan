const cache = {
  getItem: (_name: string) => '<b>local</b>'
}
const fakeElement = {
  innerHTML: '',
  insertAdjacentHTML: (_position: string, _html: string) => {}
}

const value = cache.getItem('profile')
fakeElement.innerHTML = value
fakeElement.insertAdjacentHTML('beforeend', value)

button.addEventListener('click', (event: any) => {
  fakeElement.innerHTML = event.data
})
