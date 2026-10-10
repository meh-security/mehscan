import React from "react";
function Rich({ html }: { html: string }) { return <span>{html}</span>; }
export function Render() { return <Rich html="unrelated safe text" />; }
