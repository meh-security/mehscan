package fixtures;

class JWTParser { static JWTParser parse(String token) { return new JWTParser(); } }
class PlainJWT { static void parse(String token) {} }
class Jwts { static Jwts builder() { return new Jwts(); } }

class Lookalikes {
    boolean parse(String token) {
        JWTParser.parse(token).getJWTClaimsSet();
        PlainJWT.parse(token);
        Jwts.builder().signWith(token).compact();
        return true;
    }
}
