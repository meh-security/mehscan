package fixtures;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;

class SecurityConfig {
  Object configure(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests(requests -> requests
        .requestMatchers("/public/**").permitAll()
        .requestMatchers("/admin/**").hasRole("ADMIN")
        .anyRequest().authenticated());
    return http.build();
  }
}
