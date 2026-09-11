import java.io.ObjectInputStream;
import java.security.MessageDigest;
import jakarta.servlet.http.Cookie;

class SecurityConfig {
    void review(Object input, Cookie cookie) throws Exception {
        client.hostnameVerifier((host, session) -> false);
        cookie.setSecure(false);
        cookie.setHttpOnly(false);
        MessageDigest.getInstance("MD5");
        new ObjectInputStream(input).readObject();
    }
}
