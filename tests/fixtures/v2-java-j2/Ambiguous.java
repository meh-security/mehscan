package fixtures;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

class AmbiguousController {
  AmbiguousService ambiguousService;

  @GetMapping("/ambiguous/{id}")
  Object load(@PathVariable Long id) {
    return ambiguousService.load(id);
  }
}

interface AmbiguousService {
  Object load(Long id);
}

class FirstAmbiguousService implements AmbiguousService {
  public Object load(Long id) { return id; }
}

class SecondAmbiguousService implements AmbiguousService {
  public Object load(Long id) { return id; }
}
