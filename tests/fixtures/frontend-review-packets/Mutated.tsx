import React from "react";
export function Mutated(props: { html: string }) {
  props.html = fetchReplacement();
  return <div dangerouslySetInnerHTML={{ __html: props.html }} />;
}
export function Render() { return <Mutated html="initial" />; }
