import { Basic, Strict, Append, Decode, Passthrough } from './Views';
const html = new URLSearchParams(window.location.search).get('html') ?? '';
export const Source = () => <><Basic html={html} /><Strict html={html} /><Append html={html} /><Decode html={html} /><Passthrough html={html} /></>;
