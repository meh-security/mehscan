import { unsafeHTML } from "./local-template";
import { h } from "./local-view";

export function renderLookalikes(content: string) {
  unsafeHTML(content);
  h("section", { innerHTML: content });
  return <section innerHTML={content} />;
}
