package fixtures;

import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

class ResourceController {
  ResourceService resourceService;

  @GetMapping("/resources/{id}")
  Object get(@PathVariable Long id) {
    return resourceService.find(id);
  }

  @DeleteMapping("/resources/{id}")
  void delete(@PathVariable Long id) {
    resourceService.delete(id);
  }

  @GetMapping("/resources/{id}/owned")
  Object owned(@PathVariable Long id) {
    return resourceService.findOwned(id, null);
  }
}
