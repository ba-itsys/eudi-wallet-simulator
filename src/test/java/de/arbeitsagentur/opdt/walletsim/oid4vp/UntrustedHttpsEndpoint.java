package de.arbeitsagentur.opdt.walletsim.oid4vp;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * An https endpoint that serves another verifier's request object behind a certificate no JVM
 * trusts, issued for a host it is not reached under. Both halves of certificate validation fail,
 * so a client only gets through when it verifies nothing at all.
 */
public final class UntrustedHttpsEndpoint implements AutoCloseable {

    private static final char[] PASSWORD = "changeit".toCharArray();
    private static final String WRONG_HOST = "not-localhost";

    private final HttpsServer server;

    public UntrustedHttpsEndpoint(String requestObjectUri) throws Exception {
        server = HttpsServer.create(new InetSocketAddress("localhost", 0), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(sslContext()));
        server.createContext("/request-object", exchange -> {
            byte[] body = relay(requestObjectUri);
            exchange.getResponseHeaders().add("Content-Type", "application/oauth-authz-req+jwt");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        });
        server.start();
    }

    public String requestUri() {
        return "https://localhost:" + server.getAddress().getPort() + "/request-object";
    }

    @Override
    public void close() {
        server.stop(0);
    }

    // the request object stays the verifier's, this endpoint only changes the transport it arrives over
    private static byte[] relay(String requestObjectUri) {
        try (HttpClient client = HttpClient.newHttpClient()) {
            HttpRequest request =
                    HttpRequest.newBuilder(URI.create(requestObjectUri)).build();
            return client.send(request, HttpResponse.BodyHandlers.ofString())
                    .body()
                    .getBytes(StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new IllegalStateException("Could not relay the request object", e);
        }
    }

    private static SSLContext sslContext() throws Exception {
        KeyPair keyPair = generateKeyPair();
        X509Certificate certificate = selfSigned(keyPair);
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        keyStore.setKeyEntry("tls", keyPair.getPrivate(), PASSWORD, new Certificate[] {certificate});
        KeyManagerFactory keyManagers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagers.init(keyStore, PASSWORD);
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(keyManagers.getKeyManagers(), null, null);
        return sslContext;
    }

    private static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
    }

    private static X509Certificate selfSigned(KeyPair keyPair) throws Exception {
        X500Name subject = new X500Name("CN=" + WRONG_HOST);
        Instant now = Instant.now();
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                subject,
                BigInteger.valueOf(now.toEpochMilli()),
                Date.from(now.minus(1, ChronoUnit.DAYS)),
                Date.from(now.plus(1, ChronoUnit.DAYS)),
                subject,
                keyPair.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        builder.addExtension(
                Extension.subjectAlternativeName,
                false,
                new GeneralNames(new GeneralName(GeneralName.dNSName, WRONG_HOST)));
        return new JcaX509CertificateConverter()
                .getCertificate(
                        builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.getPrivate())));
    }
}
