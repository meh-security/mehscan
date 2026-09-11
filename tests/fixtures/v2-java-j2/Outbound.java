package fixtures;

import java.net.URI;

class Outbound {
  Object load(URI endpoint) throws Exception {
    URI destination = endpoint;
    return destination.toURL().openConnection();
  }
}
