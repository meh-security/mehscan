import { render } from './barrel';
import * as helpers from './helper';
import { render as libraryRender } from 'some-library';
export const Barrel = ({ html }: { html: string }) =>
  <div dangerouslySetInnerHTML={{ __html: render(html) }} />;
export const Namespace = ({ html }: { html: string }) =>
  <div dangerouslySetInnerHTML={{ __html: helpers.render(html) }} />;
export const External = ({ html }: { html: string }) =>
  <div dangerouslySetInnerHTML={{ __html: libraryRender(html) }} />;
