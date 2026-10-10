import React from 'react';
import { Raw as Display } from './Raw';
import { Clean } from './Clean';
export function Page() {
  const query = new URLSearchParams(window.location.search);
  const html = query.get('html') ?? '';
  return <><Display html={html} /><Clean html={html} /></>;
}
