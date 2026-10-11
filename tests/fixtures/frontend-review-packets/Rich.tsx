import React from "react";
export function Rich({ html: content }: { html: string }) {
  return <div dangerouslySetInnerHTML={{ __html: content }} />;
}
