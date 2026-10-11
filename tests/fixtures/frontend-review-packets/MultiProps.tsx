export function MultiProps({ html, enabled }: { html: string; enabled: boolean }) {
  return <div dangerouslySetInnerHTML={{ __html: enabled ? html : '' }} />;
}

export function MultiObject(props: { html: string; enabled: boolean }) {
  return <div dangerouslySetInnerHTML={{ __html: props.enabled ? props.html : '' }} />;
}

export function MultiAlias({ html: markup, enabled: raw }: { html: string; enabled: boolean }) {
  return <div dangerouslySetInnerHTML={{ __html: raw ? markup : '' }} />;
}

export function PartialMulti({ html, enabled }: { html: string; enabled?: boolean }) {
  return <div dangerouslySetInnerHTML={{ __html: enabled ? html : '' }} />;
}

export function DuplicateMulti({ html, enabled }: { html: string; enabled: boolean }) {
  return <div dangerouslySetInnerHTML={{ __html: enabled ? html : '' }} />;
}

export function ManyProps({ a, b, c, d }: { a: string; b: string; c: string; d: string }) {
  return <div dangerouslySetInnerHTML={{ __html: a + b + c + d }} />;
}

export function MutatedMulti({ html, enabled }: { html: string; enabled: boolean }) {
  html = replacement();
  return <div dangerouslySetInnerHTML={{ __html: enabled ? html : '' }} />;
}

declare function replacement(): string;
