import { MultiProps, MultiObject, MultiAlias, PartialMulti, DuplicateMulti, ManyProps, MutatedMulti } from './MultiProps';
import { clean } from './MultiControl';

export function MultiCallers({ payload, allowRaw, override }: { payload: string; allowRaw: boolean; override: object }) {
  return <>
    <MultiProps html={clean(payload)} enabled={allowRaw} />
    <MultiProps html={payload} enabled={false} />
    <MultiObject html={payload} enabled />
    <MultiAlias html={payload} enabled={allowRaw} />
    <PartialMulti html={payload} />
    <PartialMulti html={payload} enabled={allowRaw} {...override} />
    <DuplicateMulti html={payload} html={clean(payload)} enabled={allowRaw} />
    <ManyProps a={payload} b={payload} c={payload} d={payload} />
    <MutatedMulti html={payload} enabled={allowRaw} />
  </>;
}

export function ShadowMulti(MultiProps: any, payload: string) {
  return <MultiProps html={payload} enabled={true} />;
}
