import React from './react-lookalike'

const target = document.querySelector('#safe')
const query = location.search
target!.textContent = query

export function SafePreview () {
  return React.createElement('div', {
    dangerouslySetInnerHTML: { value: query }
  })
}
