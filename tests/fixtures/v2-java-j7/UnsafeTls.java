import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.X509TrustManager;
import java.security.cert.X509Certificate;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustAllStrategy;
import org.apache.http.ssl.TrustStrategy;

class UnsafeTls {
    Object client(SSLContext context) {
        TrustAllStrategy trust = new TrustAllStrategy();
        SSLConnectionSocketFactory socketFactory =
            new SSLConnectionSocketFactory(context, NoopHostnameVerifier.INSTANCE);
        HostnameVerifier verifier = (host, session) -> true;
        TrustStrategy callback = (chain, authType) -> true;
        X509TrustManager manager = new X509TrustManager() {
            public void checkServerTrusted(X509Certificate[] chain, String authType) {}
            public void checkClientTrusted(X509Certificate[] chain, String authType) {}
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        };
        return socketFactory;
    }
}
