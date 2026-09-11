import java.security.MessageDigest;
import java.security.Signature;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

class TokenCrypto {
    void algorithms(char[] password) throws Exception {
        MessageDigest.getInstance("MD5");
        Cipher.getInstance("AES/ECB/PKCS5Padding");
        Cipher.getInstance("AES/CBC/PKCS5Padding");
        Mac.getInstance("HmacSHA1");
        Signature.getInstance("SHA1withRSA");
        KeyGenerator.getInstance("DES");
        SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        new SecretKeySpec(new byte[] {1, 2, 3, 4}, "AES");
        new IvParameterSpec(new byte[16]);
        new PBEKeySpec(password, new byte[] {1, 2}, 1_000, 128);
    }

    int generateToken() {
        Random random = new Random();
        return random.nextInt() + (int) Math.random();
    }
}
