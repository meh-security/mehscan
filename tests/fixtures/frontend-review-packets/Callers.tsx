import React from "react";
import DOMPurify from "dompurify";
import { Rich as Preview } from "./Rich";
function clean(value: string) {
  return DOMPurify.sanitize(value, { USE_PROFILES: { html: true } });
}
export function Render({ untrusted }: { untrusted: string }) {
  const markup = clean(untrusted);
  return <><Preview html={markup} /><Preview html={untrusted} /></>;
}
export function Shadow(Preview: any) {
  return <Preview html="unrelated shadow" />;
}
