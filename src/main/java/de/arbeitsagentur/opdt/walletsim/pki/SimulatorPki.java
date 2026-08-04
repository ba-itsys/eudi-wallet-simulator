package de.arbeitsagentur.opdt.walletsim.pki;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import java.io.FileReader;
import java.io.FileWriter;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * The simulator PKI: a P-256 CA (the trust anchor published via the trust lists) with leaf
 * certificates for credential issuance, the wallet provider, and the registrar, plus the holder
 * binding key. All material is persisted as PEM files under {@code app.pki.dir} and reloaded on
 * restart, so trust lists and registration certificates stay valid across restarts.
 */
@Component
public class SimulatorPki {

    private static final X500Name CA_NAME = new X500Name("CN=EUDI Wallet Simulator CA,O=EUDI Wallet Simulator");
    private static final X500Name ISSUER_NAME = new X500Name("CN=EUDI Wallet Simulator Issuer,O=EUDI Wallet Simulator");
    private static final X500Name WALLET_PROVIDER_NAME =
            new X500Name("CN=EUDI Wallet Simulator Wallet Provider,O=EUDI Wallet Simulator");
    private static final X500Name REGISTRAR_NAME =
            new X500Name("CN=EUDI Wallet Simulator Registrar,O=EUDI Wallet Simulator");

    private final Path pkiDir;
    private final KeyPair caKeyPair;
    private final X509Certificate caCertificate;
    private final KeyPair issuerKeyPair;
    private final X509Certificate issuerCertificate;
    private final KeyPair walletProviderKeyPair;
    private final X509Certificate walletProviderCertificate;
    private final KeyPair registrarKeyPair;
    private final X509Certificate registrarCertificate;
    private final ECKey holderKey;

    public SimulatorPki(@Value("${app.pki.dir}") Path pkiDir) {
        try {
            this.pkiDir = pkiDir;
            Files.createDirectories(pkiDir);
            this.caKeyPair = loadOrCreateKeyPair("ca");
            this.caCertificate = loadOrCreateCertificate("ca", () -> selfSignedCa(caKeyPair));
            this.issuerKeyPair = loadOrCreateKeyPair("issuer");
            this.issuerCertificate = loadOrCreateCertificate(
                    "issuer", () -> leafCertificate(ISSUER_NAME, issuerKeyPair, caKeyPair, caCertificate));
            this.walletProviderKeyPair = loadOrCreateKeyPair("wallet-provider");
            this.walletProviderCertificate = loadOrCreateCertificate(
                    "wallet-provider",
                    () -> leafCertificate(WALLET_PROVIDER_NAME, walletProviderKeyPair, caKeyPair, caCertificate));
            this.registrarKeyPair = loadOrCreateKeyPair("registrar");
            this.registrarCertificate = loadOrCreateCertificate(
                    "registrar", () -> leafCertificate(REGISTRAR_NAME, registrarKeyPair, caKeyPair, caCertificate));
            KeyPair holderKeyPair = loadOrCreateKeyPair("holder");
            this.holderKey = new ECKey.Builder(Curve.P_256, (ECPublicKey) holderKeyPair.getPublic())
                    .privateKey(holderKeyPair.getPrivate())
                    .build();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to initialize simulator PKI in " + pkiDir, e);
        }
    }

    public X509Certificate caCertificate() {
        return caCertificate;
    }

    public X509Certificate issuerCertificate() {
        return issuerCertificate;
    }

    public PrivateKey issuerPrivateKey() {
        return issuerKeyPair.getPrivate();
    }

    public PrivateKey caPrivateKey() {
        return caKeyPair.getPrivate();
    }

    public X509Certificate walletProviderCertificate() {
        return walletProviderCertificate;
    }

    public PrivateKey walletProviderPrivateKey() {
        return walletProviderKeyPair.getPrivate();
    }

    public X509Certificate registrarCertificate() {
        return registrarCertificate;
    }

    public PrivateKey registrarPrivateKey() {
        return registrarKeyPair.getPrivate();
    }

    /** Holder key pair used for credential binding (cnf.jwk) and key-binding JWTs. */
    public ECKey holderKey() {
        return holderKey;
    }

    private KeyPair loadOrCreateKeyPair(String name) throws Exception {
        Path privateKeyFile = pkiDir.resolve(name + "-key.pem");
        Path publicKeyFile = pkiDir.resolve(name + "-pub.pem");
        if (Files.exists(privateKeyFile) && Files.exists(publicKeyFile)) {
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            try (PEMParser privateParser = new PEMParser(new FileReader(privateKeyFile.toFile()));
                    PEMParser publicParser = new PEMParser(new FileReader(publicKeyFile.toFile()))) {
                PrivateKeyInfo privateKeyInfo =
                        switch (privateParser.readObject()) {
                            case PEMKeyPair pemKeyPair -> pemKeyPair.getPrivateKeyInfo();
                            case PrivateKeyInfo info -> info;
                            case Object other ->
                                throw new IllegalStateException("Unexpected PEM content in " + privateKeyFile + ": "
                                        + other.getClass().getName());
                        };
                SubjectPublicKeyInfo publicKeyInfo = (SubjectPublicKeyInfo) publicParser.readObject();
                return new KeyPair(converter.getPublicKey(publicKeyInfo), converter.getPrivateKey(privateKeyInfo));
            }
        }
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair keyPair = generator.generateKeyPair();
        writePem(privateKeyFile, new JcaPKCS8Generator(keyPair.getPrivate(), null));
        writePem(publicKeyFile, keyPair.getPublic());
        return keyPair;
    }

    private X509Certificate loadOrCreateCertificate(String name, CertificateSupplier supplier) throws Exception {
        Path file = pkiDir.resolve(name + "-cert.pem");
        if (Files.exists(file)) {
            try (PEMParser parser = new PEMParser(new FileReader(file.toFile()))) {
                X509CertificateHolder holder = (X509CertificateHolder) parser.readObject();
                return new JcaX509CertificateConverter().getCertificate(holder);
            }
        }
        X509Certificate certificate = supplier.get();
        writePem(file, certificate);
        return certificate;
    }

    private static void writePem(Path file, Object pemObject) throws Exception {
        try (JcaPEMWriter writer = new JcaPEMWriter(new FileWriter(file.toFile()))) {
            writer.writeObject(pemObject);
        }
    }

    @FunctionalInterface
    private interface CertificateSupplier {
        X509Certificate get() throws Exception;
    }

    private static X509Certificate selfSignedCa(KeyPair keyPair) throws Exception {
        Instant now = Instant.now();
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                CA_NAME,
                BigInteger.valueOf(now.toEpochMilli()),
                Date.from(now.minus(1, ChronoUnit.HOURS)),
                Date.from(now.plus(10 * 365, ChronoUnit.DAYS)),
                CA_NAME,
                keyPair.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        return new JcaX509CertificateConverter()
                .getCertificate(
                        builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.getPrivate())));
    }

    private static X509Certificate leafCertificate(
            X500Name subject, KeyPair leafKeyPair, KeyPair caKeyPair, X509Certificate caCertificate) throws Exception {
        Instant now = Instant.now();
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                new X500Name(caCertificate.getSubjectX500Principal().getName()),
                BigInteger.valueOf(now.toEpochMilli() + 1),
                Date.from(now.minus(1, ChronoUnit.HOURS)),
                Date.from(now.plus(2 * 365, ChronoUnit.DAYS)),
                subject,
                leafKeyPair.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        return new JcaX509CertificateConverter()
                .getCertificate(
                        builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(caKeyPair.getPrivate())));
    }
}
