package fixtures;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.PlainJWT;
import io.jsonwebtoken.Jwts;

class UnsafeJwt {
    String claims(String token) throws Exception {
        return JWTParser.parse(token).getJWTClaimsSet().getSubject();
    }

    boolean acceptsPlain(String token) throws Exception {
        PlainJWT.parse(token);
        return true;
    }

    Object verifier(JWSHeader header) throws Exception {
        Object alg = header.getAlgorithm();
        if (alg.getName().equals("HS256")) {
            return new MACVerifier("secret");
        }
        return new RSASSAVerifier(null);
    }

    void remoteKey(JWSHeader header) throws Exception {
        header.getJWKURL().toURI().toURL().openConnection();
    }

    String key(JWSHeader header) {
        String kid = header.getKeyID();
        return kid.contains("/dev/null") ? "AA==" : kid;
    }

    String apiKey(Object key) {
        return Jwts.builder().subject("user").signWith(key).compact();
    }
}
