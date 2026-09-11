function review(query, url, path, code) {
  pool.query(query);
  fetch(url);
  fs.readFileSync(path);
  fs.writeFileSync(path, "content");
  eval(code);
}

