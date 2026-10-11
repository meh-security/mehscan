import { useState } from 'react';
export function ManyWriters({ a, b, c, d }: { a: string; b: string; c: string; d: string }) {
  const [html, setHtml] = useState('');
  const first = () => setHtml(a);
  const second = () => setHtml(b);
  const third = () => setHtml(c);
  const fourth = () => setHtml(d);
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}
