import DOMPurify from 'dompurify';
export async function fetchRows(url: string) { return (await fetch(url)).json(); }
export function clean(html: string) { return DOMPurify.sanitize(html); }
