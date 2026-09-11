import java.util.List;
import org.springframework.web.cors.CorsConfiguration;

class CorsPolicy {
    void unsafe() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(List.of("*"));
        configuration.setAllowCredentials(true);
    }

    void review() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(List.of("https://example.test"));
        configuration.setAllowCredentials(true);
    }
}
