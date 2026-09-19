import React from "react";
import { DomSanitizer } from "@angular/platform-browser";
import { unsafeHTML as renderUnsafeHtml } from "lit/directives/unsafe-html.js";
import { createSignal } from "solid-js";
import { h as createVueNode } from "vue";

export function renderTrustedHtml(sanitizer: DomSanitizer, content: string) {
  const Card = (_props: { innerHTML: string }) => null;
  sanitizer.bypassSecurityTrustHtml(content);
  renderUnsafeHtml(content);
  createVueNode("section", { innerHTML: content });
  const solid = <section innerHTML={content} />;
  const custom = <Card innerHTML={content} />;
  const react = <section dangerouslySetInnerHTML={{ __html: content }} />;
  return [solid, custom, react, createSignal(content)];
}
