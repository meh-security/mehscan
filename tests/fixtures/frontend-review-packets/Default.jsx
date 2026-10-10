import React from "react";
export default function Panel(props) {
  return <div dangerouslySetInnerHTML={{ __html: props.html }} />;
}
