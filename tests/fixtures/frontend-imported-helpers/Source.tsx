import { Noop, Page } from './Page';
const payload = new URLSearchParams(window.location.search).get('html') ?? '';
export const Source = () => <><Page html={payload} /><Noop html={payload} /></>;
