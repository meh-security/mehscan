import { makeQuery as selectedQuery, makePath } from './helpers';
import { makeCommand } from './driver';
import * as mysql from 'mysql2';
import * as fs from 'node:fs';
import * as child_process from 'node:child_process';
declare const req: { query: { q: string } };
declare const res: { send(content: string): void };
const marker = '🙂';
const db = mysql.createConnection({});
export function search() { return db.query(selectedQuery(req.query.q)); }
export function read() { return fs.readFileSync(makePath(req.query.q)); }
export function execute() { return child_process.exec(makeCommand(req.query.q)); }
export function render() { const markup = selectedQuery(req.query.q); res.send(markup); }
