import { Nested, NamedNested, ShadowParameter, ShadowBlock, MutatedNested, ClassBoundary } from './Nested';

export function NestedCallers({ source }: { source: string }) {
  return <>
    <Nested description={source} />
    <NamedNested html={source} />
    <ShadowParameter html={source} />
    <ShadowBlock html={source} />
    <MutatedNested html={source} />
    <ClassBoundary html={source} />
  </>;
}
