import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

class JsonOnly {
    @GetMapping(value = "/data", produces = "application/json")
    ResponseEntity<String> data(@RequestParam String value) {
        return ResponseEntity.ok().body(value);
    }

    void writeJson(String value, HttpServletResponse response) throws Exception {
        response.setContentType("application/json");
        response.getWriter().write(value);
    }
}
