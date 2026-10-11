import React from "react";
import { PreviewMemo as Preview } from "./Memo";
interface Broken { field: ; }
export function Render(value: string) {
  return <Preview data={value} />;
}
