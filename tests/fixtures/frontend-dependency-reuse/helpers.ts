import createDOMPurify from 'dompurify';
const cleaner = createDOMPurify(window);
const STRICT = { ALLOWED_TAGS: ['b', 'p'], ALLOWED_ATTR: [] };
export const basic = (html: string) => cleaner.sanitize(html);
export const strict = (html: string) => cleaner.sanitize(html, STRICT);
export const append = (html: string) => cleaner.sanitize(html) + html;
export const decode = (html: string) => decodeURIComponent(cleaner.sanitize(html));
export const normalize = (html: string) => html;
