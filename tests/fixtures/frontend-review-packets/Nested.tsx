export function Nested({ description }: { description: string | (() => string) }) {
  const renderContent = () => {
    const html = typeof description === 'function' ? description() : description;
    return <div dangerouslySetInnerHTML={{ __html: html }} />;
  };
  return renderContent();
}

export function NamedNested(props: { html: string }) {
  function renderContent() {
    return <div dangerouslySetInnerHTML={{ __html: props.html }} />;
  }
  return renderContent();
}

export function ShadowParameter({ html }: { html: string }) {
  const renderContent = (html: string) => <div dangerouslySetInnerHTML={{ __html: html }} />;
  return renderContent(otherHtml());
}

export function ShadowBlock({ html }: { html: string }) {
  const renderContent = () => {
    const html = otherHtml();
    return <div dangerouslySetInnerHTML={{ __html: html }} />;
  };
  return renderContent();
}

export function MutatedNested({ html }: { html: string }) {
  const renderContent = () => {
    html = otherHtml();
    return <div dangerouslySetInnerHTML={{ __html: html }} />;
  };
  return renderContent();
}

export function ClassBoundary({ html }: { html: string }) {
  class Inner {
    render() {
      return <div dangerouslySetInnerHTML={{ __html: html }} />;
    }
  }
  return new Inner().render();
}

declare function otherHtml(): string;
