function review(serialized) {
  localTls.connect({ verifyPeer: false });
  response.localCookie("transport", "value", { secure: false });
  response.localCookie("script", "value", { httpOnly: false });
  crypto.safeHash("md5");
  safeYaml.load(serialized);
}
