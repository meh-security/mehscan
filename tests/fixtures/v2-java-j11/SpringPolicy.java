import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;

class SpringPolicy {
    void unsafe(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.cors(Customizer.withDefaults());
        http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED));
        http.sessionManagement(session -> session.sessionFixation().none());
    }

    void safe(HttpSecurity http) throws Exception {
        http.csrf(Customizer.withDefaults());
        http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        http.sessionManagement(session -> session.sessionFixation().migrateSession());
    }
}
