import React from "react";
import { PreviewMemo as Display } from "./Memo";
export function Render({ value }: { value: string }) {
  return <Display data={value} />;
}
