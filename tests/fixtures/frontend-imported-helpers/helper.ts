import makeCleaner from 'dompurify';
const cleaner = makeCleaner(window);
const OPTIONS = { ALLOW_DATA_ATTR: false };
const ATTRS = ['href', 'src'];
cleaner.addHook('afterSanitizeAttributes', (node) => {
  for (const attr of ATTRS) {
    if (node.getAttribute(attr)?.startsWith('data:')) node.removeAttribute(attr);
  }
});
const clean = (html: string) => cleaner.sanitize(html, OPTIONS);
export { clean as render };
export const sanitize = (html: string) => html; // A name is not a control.
