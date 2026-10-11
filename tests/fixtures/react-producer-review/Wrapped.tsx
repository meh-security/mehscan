import React, { memo as cache, forwardRef } from 'react';
interface Props { html: string }
export const Wrapped = cache(forwardRef(function Render(props: Props, ref) {
  const html = props.html;
  return <div ref={ref} dangerouslySetInnerHTML={{ __html: html }} />;
}));
export function RenderWrapped(props: Props) { return <Wrapped html={props.html} />; }
export const NamespaceWrapped = React.memo((props: Props) => <div dangerouslySetInnerHTML={{ __html: props.html }} />);
export function RenderNamespace(props: Props) { return <NamespaceWrapped html={props.html} />; }
