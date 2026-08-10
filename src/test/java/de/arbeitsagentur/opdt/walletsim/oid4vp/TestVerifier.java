package de.arbeitsagentur.opdt.walletsim.oid4vp;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
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
import java.security.MessageDigest;
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
import java.util.concurrent.TimeUnit;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import tools.jackson.databind.ObjectMapper;

/**
 * Minimal in-JVM OID4VP verifier: serves a signed request object on request_uri and captures the
 * wallet's direct_post response, answering with a same-device redirect_uri.
 */
public final class TestVerifier implements AutoCloseable {

    private static final String PID_DCQL_QUERY =
            """
            {"credentials": [{
                "id": "pid",
                "format": "dc+sd-jwt",
                "meta": {"vct_values": ["urn:eudi:pid:1"]},
                "claims": [{"path": ["family_name"]}, {"path": ["given_name"]}]
            }]}
            """;

    public static TestVerifier pidVerifier() throws Exception {
        return new TestVerifier(PID_DCQL_QUERY);
    }

    public record ReceivedResponse(Map<String, String> formParameters) {}

    // Mutates the request object claims before signing, to simulate non-conformant verifiers.
    @FunctionalInterface
    public interface RequestCustomizer {
        void customize(Map<String, Object> claims);
    }

    private final HttpServer server;
    private final KeyPair keyPair;
    private final X509Certificate certificate;
    private final String nonce = UUID.randomUUID().toString();
    private final String state = UUID.randomUUID().toString();
    private final CompletableFuture<ReceivedResponse> received = new CompletableFuture<>();
    private final String dcqlQueryJson;
    private RequestCustomizer requestCustomizer = claims -> {};
    private ECKey responseEncryptionKey;
    private String verifierInfoJson;

    public TestVerifier(String dcqlQueryJson) throws Exception {
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

    public TestVerifier withRequestCustomizer(RequestCustomizer customizer) {
        this.requestCustomizer = customizer;
        return this;
    }

    // Adds a verifier_info claim, e.g. the value from the simulator's registration certificate API.
    public TestVerifier withVerifierInfo(String verifierInfoJson) {
        this.verifierInfoJson = verifierInfoJson;
        return this;
    }

    // Switches to direct_post.jwt with an ephemeral encryption key whose kid is the flow state.
    public TestVerifier withEncryptedResponses() throws Exception {
        this.responseEncryptionKey =
                new ECKeyGenerator(Curve.P_256).keyID(state).generate();
        return this;
    }

    public ECKey responseEncryptionKey() {
        return responseEncryptionKey;
    }

    public String clientId() {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded());
            return "x509_hash:" + Base64URL.encode(hash).toString();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public String nonce() {
        return nonce;
    }

    public String state() {
        return state;
    }

    public String requestUri() {
        return baseUrl() + "/request-object";
    }

    public String responseUri() {
        return baseUrl() + "/callback";
    }

    public String redirectUri() {
        return baseUrl() + "/complete-auth?state=" + state;
    }

    public X509Certificate certificate() {
        return certificate;
    }

    public ReceivedResponse awaitResponse() throws Exception {
        return received.get(TimeUnit.SECONDS.toMillis(10), TimeUnit.MILLISECONDS);
    }

    private String baseUrl() {
        return "http://localhost:" + server.getAddress().getPort();
    }

    private String requestObjectJwt() {
        try {
            Instant now = Instant.now();
            Map<String, Object> claims = new LinkedHashMap<>();
            claims.put("jti", UUID.randomUUID().toString());
            claims.put("iss", clientId());
            claims.put("aud", "https://self-issued.me/v2");
            claims.put("client_id", clientId());
            claims.put("response_type", "vp_token");
            claims.put("response_mode", responseEncryptionKey != null ? "direct_post.jwt" : "direct_post");
            claims.put("response_uri", responseUri());
            claims.put("nonce", nonce);
            claims.put("state", state);
            claims.put("client_metadata", clientMetadata());
            claims.put("dcql_query", new ObjectMapper().readValue(dcqlQueryJson, Map.class));
            if (verifierInfoJson != null) {
                claims.put("verifier_info", new ObjectMapper().readValue(verifierInfoJson, List.class));
            }
            requestCustomizer.customize(claims);

            JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                    .issueTime(Date.from(now))
                    .expirationTime(Date.from(now.plus(5, ChronoUnit.MINUTES)));
            claims.forEach(builder::claim);
            SignedJWT jwt = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.ES256)
                            .type(new JOSEObjectType("oauth-authz-req+jwt"))
                            .x509CertChain(List.of(Base64.encode(certificate.getEncoded())))
                            .build(),
                    builder.build());
            jwt.sign(new ECDSASigner((ECPrivateKey) keyPair.getPrivate()));
            return jwt.serialize();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private Map<String, Object> clientMetadata() {
        if (responseEncryptionKey == null) {
            return Map.of("vp_formats_supported", Map.of("dc+sd-jwt", Map.of()));
        }
        return Map.of(
                "vp_formats_supported",
                Map.of("dc+sd-jwt", Map.of()),
                "jwks",
                Map.of("keys", List.of(responseEncryptionKey.toPublicJWK().toJSONObject())),
                "encrypted_response_enc_values_supported",
                List.of("A128GCM", "A256GCM"));
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
