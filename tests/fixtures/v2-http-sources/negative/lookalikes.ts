function review(config: any) {
  return config.body.email + config.query.q + config.params.id;
}
