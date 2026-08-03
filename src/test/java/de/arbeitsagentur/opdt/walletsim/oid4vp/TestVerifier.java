package de.arbeitsagentur.opdt.walletsim.oid4vp;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpServer;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Minimal in-JVM OID4VP verifier: serves a signed request object on request_uri and captures the
 * wallet's direct_post response, answering with a same-device redirect_uri like
 * keycloak-extension-oid4vp does.
 */
final class TestVerifier implements AutoCloseable {

    record ReceivedResponse(Map<String, String> formParameters) {}

    private final HttpServer server;
    private final KeyPair keyPair;
    private final X509Certificate certificate;
    private final String nonce = UUID.randomUUID().toString();
    private final String state = UUID.randomUUID().toString();
    private final CompletableFuture<ReceivedResponse> received = new CompletableFuture<>();
    private final String dcqlQueryJson;

    TestVerifier(String dcqlQueryJson) throws Exception {
        this.dcqlQueryJson = dcqlQueryJson;
        this.keyPair = generateKeyPair();
        this.certificate = selfSignedWithSanDns(keyPair, "verifier.example.com");
        this.server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        server.createContext("/request-object", exchange -> {
            byte[] body = requestObjectJwt().getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/oauth-authz-req+jwt");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        });
        server.createContext("/callback", exchange -> {
            String form = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            received.complete(new ReceivedResponse(parseForm(form)));
            byte[] body = ("{\"redirect_uri\":\"" + redirectUri() + "\"}").getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        });
        server.start();
    }

    String clientId() {
        return "x509_san_dns:verifier.example.com";
    }

    String nonce() {
        return nonce;
    }

    String state() {
        return state;
    }

    String requestUri() {
        return baseUrl() + "/request-object";
    }

    String responseUri() {
        return baseUrl() + "/callback";
    }

    String redirectUri() {
        return baseUrl() + "/complete-auth?state=" + state;
    }

    X509Certificate certificate() {
        return certificate;
    }

    ReceivedResponse awaitResponse() throws Exception {
        return received.get(
                java.util.concurrent.TimeUnit.SECONDS.toMillis(10), java.util.concurrent.TimeUnit.MILLISECONDS);
    }

    private String baseUrl() {
        return "http://localhost:" + server.getAddress().getPort();
    }

    private String requestObjectJwt() {
        try {
            Instant now = Instant.now();
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .jwtID(UUID.randomUUID().toString())
                    .issuer(clientId())
                    .audience("https://self-issued.me/v2")
                    .issueTime(Date.from(now))
                    .expirationTime(Date.from(now.plus(5, ChronoUnit.MINUTES)))
                    .claim("client_id", clientId())
                    .claim("response_type", "vp_token")
                    .claim("response_mode", "direct_post")
                    .claim("response_uri", responseUri())
                    .claim("nonce", nonce)
                    .claim("state", state)
                    .claim("client_metadata", Map.of("vp_formats_supported", Map.of("dc+sd-jwt", Map.of())))
                    .claim("dcql_query", new tools.jackson.databind.ObjectMapper().readValue(dcqlQueryJson, Map.class))
                    .build();
            SignedJWT jwt = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.ES256)
                            .type(new JOSEObjectType("oauth-authz-req+jwt"))
                            .x509CertChain(List.of(Base64.encode(certificate.getEncoded())))
                            .build(),
                    claims);
            jwt.sign(new ECDSASigner((ECPrivateKey) keyPair.getPrivate()));
            return jwt.serialize();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static Map<String, String> parseForm(String form) {
        Map<String, String> parameters = new LinkedHashMap<>();
        for (String pair : form.split("&")) {
            int eq = pair.indexOf('=');
            parameters.put(
                    URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8),
                    URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8));
        }
        return parameters;
    }

    private static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
    }

    private static X509Certificate selfSignedWithSanDns(KeyPair keyPair, String dnsName) throws Exception {
        Instant now = Instant.now();
        X500Name name = new X500Name("CN=" + dnsName);
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                name,
                BigInteger.valueOf(now.toEpochMilli()),
                Date.from(now.minus(1, ChronoUnit.HOURS)),
                Date.from(now.plus(365, ChronoUnit.DAYS)),
                name,
                keyPair.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        builder.addExtension(
                Extension.subjectAlternativeName,
                false,
                new GeneralNames(new GeneralName(GeneralName.dNSName, dnsName)));
        return new JcaX509CertificateConverter()
                .getCertificate(
                        builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.getPrivate())));
    }

    @Override
    public void close() {
        server.stop(0);
    }
}
