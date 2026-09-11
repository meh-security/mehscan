package fixtures;

import com.nimbusds.jwt.SignedJWT;
import io.jsonwebtoken.Jwts;

class SafeJwt {
    boolean verify(String token, Object verifier) throws Exception {
        SignedJWT jwt = SignedJWT.parse(token);
        return jwt.verify(verifier);
    }

    String session(Object key, java.util.Date expiry) {
        return Jwts.builder().subject("user").expiration(expiry).signWith(key).compact();
    }
}
