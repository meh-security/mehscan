import { createSignal } from "solid-js";
export const Raw = (props: { html: string }) => <section innerHTML={props.html} />;
export function Render(options: any) {
  return <><Raw html="fixed markup" /><Raw html="initial" {...options} /><Raw html={options.html} /></>;
}
