import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

class SpringHtml {
    @GetMapping(value = "/page", produces = MediaType.TEXT_HTML_VALUE)
    ResponseEntity<String> page(@RequestParam String value) {
        return ResponseEntity.ok().body(value);
    }

    @GetMapping("/fragment")
    ResponseEntity<String> fragment(@RequestParam String value) {
        return ResponseEntity.ok().contentType(MediaType.TEXT_HTML).body(value);
    }
}
