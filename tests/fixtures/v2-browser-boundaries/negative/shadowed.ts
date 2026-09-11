const fake = {
  location: { hash: 'local', assign: (_value: string) => {} },
  querySelector: (_selector: string) => ({ innerHTML: '' }),
  localStorage: { getItem: (_key: string) => 'local' }
}
const window = fake
const document = fake
const localStorage = fake.localStorage

const value = window.location.hash
const target = document.querySelector('#target')
target.innerHTML = localStorage.getItem(value)
window.location.assign(value)
