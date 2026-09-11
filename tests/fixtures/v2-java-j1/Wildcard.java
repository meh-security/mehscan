package fixtures;

import org.springframework.web.bind.annotation.*;

class Wildcard {
  @PatchMapping("/items/{id}")
  void update(@PathVariable String id, @RequestBody String body) {}
}
