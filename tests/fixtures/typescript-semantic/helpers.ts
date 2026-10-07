export function makeQuery(value: string) { return 'SELECT * FROM users WHERE name = ' + value; }
export function makePath(value: string) { return 'storage/' + value; }
