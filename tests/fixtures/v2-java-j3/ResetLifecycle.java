package fixtures;

import fixtures.support.EmailTokenGenerator;
import org.springframework.security.crypto.password.PasswordEncoder;

class EmailTokenRecord {
    String emailToken;
    String status;
}

class ResetLifecycle {
    PasswordEncoder encoder;
    TokenRepository repository;
    Logger log;

    void issue() {
        String token = EmailTokenGenerator.generateRandom(10);
    }

    Object consume(String token) {
        return repository.findByEmailToken(token);
    }

    void resetPassword(Object form, Object request) {
        Object user = getUserFromToken(request);
        user.setPassword(encoder.encode(form.getPassword()));
    }

    Object generateApiKey() {
        String apiKey = "value";
        log.debug("apiKey {}", apiKey);
        return apiKey;
    }

    Object generateApiKey(String account) {
        String apiKey = "value";
        log.debug("Generating key for {}", account);
        return apiKey;
    }
}
