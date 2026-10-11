import { render as filterHtml, sanitize } from './helper';
import defaultFilter from './default';
export const Page = ({ html }: { html: string }) => {
  const output = filterHtml(html);
  return <div dangerouslySetInnerHTML={{ __html: output }} />;
};
export const Noop = ({ html }: { html: string }) =>
  <div dangerouslySetInnerHTML={{ __html: sanitize(html) }} />;
export const Default = ({ html }: { html: string }) =>
  <div dangerouslySetInnerHTML={{ __html: defaultFilter(html) }} />;
export const Shadow = ({ html, filterHtml }: { html: string; filterHtml: (s: string) => string }) =>
  <div dangerouslySetInnerHTML={{ __html: filterHtml(html) }} />;
