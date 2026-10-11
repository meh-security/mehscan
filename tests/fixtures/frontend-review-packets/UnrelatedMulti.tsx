export function MultiProps({ html, enabled }: { html: string; enabled: boolean }) {
  return <section>{enabled ? html : ''}</section>;
}
export function Other({ payload }: { payload: string }) {
  return <MultiProps html={payload} enabled={true} />;
}
