import React from 'react';
interface Props { html: string }
export function Raw(props: Props) {
  const input = props.html;
  const html = `<section>${input}</section>`;
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}
