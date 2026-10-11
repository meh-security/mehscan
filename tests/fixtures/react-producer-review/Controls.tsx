import React from 'react';
import DOMPurify from 'dompurify';
import { Raw as Display } from './Raw';
function memo(callback: any) { return callback; }
export const Fake = memo((props: { html: string }) => <div dangerouslySetInnerHTML={{ __html: props.html }} />);
export function Caller() { return <Fake html="fixed" />; }
export function Shadow({ Display }: { Display: any }) { return <Display html="not the imported component" />; }
export function Local() {
  const query = new URLSearchParams(window.location.search);
  const html = DOMPurify.sanitize(query.get('html') ?? '');
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}
export function ShadowInput(props: { html: string }) {
  const html = [1].map(function (props) { return props.html; }).join('');
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}
const input = 'unrelated outer value';
export function Destructured(props: { html: string }) {
  const { html: input } = props;
  return <div dangerouslySetInnerHTML={{ __html: input }} />;
}
export function ShadowLocal(props: { html: string }) {
  const html = [1].map(() => {
    const props = getLocalRecord();
    return props.html;
  }).join('');
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}
