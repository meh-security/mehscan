import React from 'react';
import DOMPurify from 'dompurify';
interface Props { html: string }
export function Clean(props: Props) {
  const input = props.html;
  const html = DOMPurify.sanitize(input);
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}
