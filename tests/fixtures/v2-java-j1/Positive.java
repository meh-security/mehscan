package fixtures;

import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.multipart.MultipartFile;

class Positive {
  private final RestTemplate restTemplate = new RestTemplate();

  @GetMapping("/fetch")
  Object fetch(@RequestParam String endpoint) {
    return restTemplate.getForObject(endpoint, String.class);
  }

  @PostMapping("/run")
  Process run(@RequestBody String command) throws Exception {
    return Runtime.getRuntime().exec(command);
  }

  @PostMapping("/run-alias")
  Process runAlias(@RequestBody String command) throws Exception {
    Runtime runtime = Runtime.getRuntime();
    return runtime.exec(command);
  }

  @PostMapping("/all/{id}")
  void boundaries(
      @PathVariable String id,
      @RequestHeader String header,
      @CookieValue String cookie,
      @ModelAttribute Input model,
      @RequestPart MultipartFile file) {}

  static class Input {}
}
