class MessageDigest { static void getInstance(String value) {} }
class Cipher { static void getInstance(String value) {} }
class Math { static double random() { return 0; } }
class Lookalikes {
    void generateToken() {
        MessageDigest.getInstance("MD5");
        Cipher.getInstance("AES/ECB/PKCS5Padding");
        Math.random();
    }
}
