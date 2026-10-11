import React, { useState as state, useEffect } from 'react';
import { fetchRows, clean } from './api';

export function RawRow({ html }: { html: string }) {
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}

export function Feed() {
  const [rows, setRows] = state([]);
  const load = async () => {
    const response = await fetchRows('/api/items');
    if (response.items.length) setRows(response.items);
  };
  useEffect(() => { load(); }, []);
  const irrelevant = (setRows: (value: unknown) => void) => setRows(unrelated);
  return <section>{rows.map(item => <RawRow {...item} />)}</section>;
}

export function Direct({ payload }: { payload: string }) {
  const [html, setHtml] = React.useState('');
  useEffect(() => { setHtml(clean(payload)); }, [payload]);
  const replace = () => setHtml(previous => previous + payload);
  const unrelatedWriter = () => {
    const setHtml = (value: string) => console.log(value);
    setHtml(unrelated);
  };
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}

export function Escaped({ payload }: { payload: string }) {
  const [html, setHtml] = React.useState(payload);
  useEffect(() => { setHtml(payload); }, [payload]);
  return <div>{html}</div>;
}

declare const unrelated: string;
