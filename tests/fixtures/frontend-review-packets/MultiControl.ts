import DOMPurify from 'dompurify';
export function clean(html: string) {
  return DOMPurify.sanitize(html);
}
