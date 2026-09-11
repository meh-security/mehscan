function review(query: string, url: string, path: string, code: string) {
  connection.query(query);
  axios.get(url);
  fs.readFileSync(path);
  fs.writeFileSync(path, "content");
  vm.runInNewContext(code);
}

