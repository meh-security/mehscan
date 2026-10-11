import { basic, strict, append, decode, normalize } from './helpers';
export const Basic = ({ html }: { html: string }) =>
  <div dangerouslySetInnerHTML={{ __html: basic(html) }} />;
export const Strict = ({ html }: { html: string }) =>
  <div dangerouslySetInnerHTML={{ __html: strict(html) }} />;
export const Append = ({ html }: { html: string }) =>
  <div dangerouslySetInnerHTML={{ __html: append(html) }} />;
export const Decode = ({ html }: { html: string }) =>
  <div dangerouslySetInnerHTML={{ __html: decode(html) }} />;
export const Passthrough = ({ html }: { html: string }) =>
  <div dangerouslySetInnerHTML={{ __html: normalize(html) }} />;
