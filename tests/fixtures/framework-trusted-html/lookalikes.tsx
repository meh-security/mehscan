import { unsafeHTML } from "./local-template";
import { h } from "./local-view";

export function renderLookalikes(content: string) {
  unsafeHTML(content);
  h("section", { innerHTML: content });
  const Card = (_props: { innerHTML: string }) => null;
  const fake = { setHTMLUnsafe: (_value: string) => undefined };
  fake.setHTMLUnsafe(content);
  const wrapped = { html: (_value: string) => undefined };
  wrapped.html(content);
  const sanitizer = { bypassSecurityTrustHtml: (_value: string) => undefined };
  sanitizer.bypassSecurityTrustHtml(content);
  return <Card innerHTML={content} />;
}
