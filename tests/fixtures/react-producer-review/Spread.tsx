import React from 'react';
import { Raw } from './Raw';
export function Spread() {
  const options = { html: window.location.search };
  return <Raw {...options} />;
}
