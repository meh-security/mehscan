import React from 'react'

export function Preview () {
  const content = window.location.search
  return <section dangerouslySetInnerHTML={{ __html: content }} />
}

export function StoredPreview () {
  const content = sessionStorage.getItem('preview') ?? ''
  return React.createElement('div', {
    dangerouslySetInnerHTML: { __html: content }
  })
}
