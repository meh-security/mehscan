import React from "react";
import DOMPurify from "dompurify";
const Memo = ({ data }: { data: string }) => {
  const html = React.useMemo(() => DOMPurify.sanitize(data), [data]);
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
};
export { Memo as PreviewMemo };
