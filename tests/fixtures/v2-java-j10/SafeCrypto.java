import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;

class SafeTokenCrypto {
    void algorithms(char[] password, byte[] salt, byte[] nonce) throws Exception {
        MessageDigest.getInstance("SHA-256");
        Cipher.getInstance("AES/GCM/NoPadding");
        Mac.getInstance("HmacSHA256");
        Signature.getInstance("SHA256withRSA");
        KeyGenerator.getInstance("AES");
        SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        new GCMParameterSpec(128, nonce);
        new PBEKeySpec(password, salt, 210_000, 256);
    }

    void generateToken(byte[] token) {
        SecureRandom random = new SecureRandom();
        random.nextBytes(token);
    }
}
