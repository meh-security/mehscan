import { useState } from './fake';

export function FakeHook({ input }: { input: string }) {
  const [html, setHtml] = useState(input);
  const update = () => setHtml(input);
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}

export function ShadowHook(useState: any, input: string) {
  const [html, setHtml] = useState(input);
  const update = () => setHtml(input);
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}
