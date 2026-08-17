package de.arbeitsagentur.opdt.walletsim.pki;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import java.io.ByteArrayOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * The simulator PKI: a P-256 CA (the trust anchor published via the trust lists) with leaf
 * certificates for credential issuance, the wallet provider, and the registrar, plus the holder
 * binding key. With {@code app.pki.seed} set, all material is derived from the seed in memory, so
 * every start yields byte identical keys and certificates without touching the filesystem.
 * Without a seed, the material is persisted as PEM files under {@code app.pki.dir} and reloaded
 * on restart. Either way, trust lists and registration certificates stay valid across restarts.
 */
@Component
public class SimulatorPki {

    private static final X500Name CA_NAME = new X500Name("CN=EUDI Wallet Simulator CA,O=EUDI Wallet Simulator");
    private static final X500Name ISSUER_NAME = new X500Name("CN=EUDI Wallet Simulator Issuer,O=EUDI Wallet Simulator");
    private static final X500Name WALLET_PROVIDER_NAME =
            new X500Name("CN=EUDI Wallet Simulator Wallet Provider,O=EUDI Wallet Simulator");
    private static final X500Name REGISTRAR_NAME =
            new X500Name("CN=EUDI Wallet Simulator Registrar,O=EUDI Wallet Simulator");
    private static final SecureRandom RANDOM = new SecureRandom();

    private static final String HKDF_SALT = "eudi-wallet-simulator-pki";

    // fixed so the certificates come out byte identical no matter when an instance starts
    private static final Instant SEEDED_NOT_BEFORE = Instant.parse("2025-01-01T00:00:00Z");
    private static final Instant SEEDED_NOT_AFTER = Instant.parse("2075-01-01T00:00:00Z");

    // deterministic ECDSA (RFC 6979) needs the BC provider; kept off the global provider list
    private static final BouncyCastleProvider DETERMINISTIC_PROVIDER = new BouncyCastleProvider();

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

    public SimulatorPki(@Value("${app.pki.dir}") Path pkiDir, @Value("${app.pki.seed:}") String seed) {
        try {
            this.pkiDir = pkiDir;
            if (seed != null && !seed.isBlank()) {
                this.caKeyPair = deriveKeyPair(seed, "ca");
                this.caCertificate = selfSignedCa(caKeyPair, seededStamp(seed, "ca"));
                this.issuerKeyPair = deriveKeyPair(seed, "issuer");
                this.issuerCertificate = leafCertificate(
                        ISSUER_NAME, issuerKeyPair, caKeyPair, caCertificate, seededStamp(seed, "issuer"));
                this.walletProviderKeyPair = deriveKeyPair(seed, "wallet-provider");
                this.walletProviderCertificate = leafCertificate(
                        WALLET_PROVIDER_NAME,
                        walletProviderKeyPair,
                        caKeyPair,
                        caCertificate,
                        seededStamp(seed, "wallet-provider"));
                this.registrarKeyPair = deriveKeyPair(seed, "registrar");
                this.registrarCertificate = leafCertificate(
                        REGISTRAR_NAME, registrarKeyPair, caKeyPair, caCertificate, seededStamp(seed, "registrar"));
                this.holderKey = toEcKey(deriveKeyPair(seed, "holder"));
            } else {
                Files.createDirectories(pkiDir);
                this.caKeyPair = loadOrCreateKeyPair("ca");
                this.caCertificate = loadOrCreateCertificate("ca", () -> selfSignedCa(caKeyPair, randomCaStamp()));
                this.issuerKeyPair = loadOrCreateKeyPair("issuer");
                this.issuerCertificate = loadOrCreateCertificate(
                        "issuer",
                        () -> leafCertificate(ISSUER_NAME, issuerKeyPair, caKeyPair, caCertificate, randomLeafStamp()));
                this.walletProviderKeyPair = loadOrCreateKeyPair("wallet-provider");
                this.walletProviderCertificate = loadOrCreateCertificate(
                        "wallet-provider",
                        () -> leafCertificate(
                                WALLET_PROVIDER_NAME,
                                walletProviderKeyPair,
                                caKeyPair,
                                caCertificate,
                                randomLeafStamp()));
                this.registrarKeyPair = loadOrCreateKeyPair("registrar");
                this.registrarCertificate = loadOrCreateCertificate(
                        "registrar",
                        () -> leafCertificate(
                                REGISTRAR_NAME, registrarKeyPair, caKeyPair, caCertificate, randomLeafStamp()));
                this.holderKey = toEcKey(loadOrCreateKeyPair("holder"));
            }
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

    // The persisted wallet-instance key, used for wallet attestations and their PoP JWTs.
    public ECKey holderKey() {
        return holderKey;
    }

    // Fresh P-256 binding key for a single credential (cnf.jwk); never persisted.
    public ECKey generateCredentialBindingKey() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair keyPair = generator.generateKeyPair();
            return toEcKey(keyPair);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to generate credential binding key", e);
        }
    }

    private static ECKey toEcKey(KeyPair keyPair) {
        return new ECKey.Builder(Curve.P_256, (ECPublicKey) keyPair.getPublic())
                .privateKey(keyPair.getPrivate())
                .build();
    }

    /**
     * Derives the P-256 key pair for one PKI name from the seed: HKDF-SHA256 with the name as the
     * info label yields the private scalar, so every name gets an independent key and the same
     * seed always yields the same pair.
     */
    private static KeyPair deriveKeyPair(String seed, String name) throws Exception {
        X9ECParameters curve = ECNamedCurveTable.getByName("secp256r1");
        BigInteger d = new BigInteger(1, hkdf(seed, name + "/key", 40))
                .mod(curve.getN().subtract(BigInteger.ONE))
                .add(BigInteger.ONE);
        ECPoint q = curve.getG().multiply(d).normalize();
        ECNamedDomainParameters domain = new ECNamedDomainParameters(
                SECObjectIdentifiers.secp256r1, curve.getCurve(), curve.getG(), curve.getN(), curve.getH());
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
        PrivateKey privateKey = converter.getPrivateKey(
                PrivateKeyInfoFactory.createPrivateKeyInfo(new ECPrivateKeyParameters(d, domain)));
        PublicKey publicKey = converter.getPublicKey(
                SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(new ECPublicKeyParameters(q, domain)));
        return new KeyPair(publicKey, privateKey);
    }

    private static byte[] hkdf(String seed, String info, int length) {
        HKDFBytesGenerator generator = new HKDFBytesGenerator(new SHA256Digest());
        generator.init(new HKDFParameters(
                seed.getBytes(StandardCharsets.UTF_8),
                HKDF_SALT.getBytes(StandardCharsets.UTF_8),
                info.getBytes(StandardCharsets.UTF_8)));
        byte[] out = new byte[length];
        generator.generateBytes(out, 0, length);
        return out;
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
                X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(holder);
                // certificates persisted before key identifier support are upgraded in place
                if (certificate.getExtensionValue(Extension.subjectKeyIdentifier.getId()) != null) {
                    return certificate;
                }
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

    /**
     * How a certificate is stamped and signed. The persisted PKI stamps with a random serial,
     * clock based validity and randomized ECDSA. The seeded PKI stamps with a seed derived serial,
     * a fixed validity window and deterministic ECDSA, so its certificates are byte identical on
     * every start.
     */
    private record CertificateStamp(BigInteger serial, Date notBefore, Date notAfter, SignerFactory signer) {}

    @FunctionalInterface
    private interface SignerFactory {
        ContentSigner create(PrivateKey signingKey) throws Exception;
    }

    private static CertificateStamp randomCaStamp() {
        Instant now = Instant.now();
        return new CertificateStamp(
                serialNumber(),
                Date.from(now.minus(1, ChronoUnit.HOURS)),
                Date.from(now.plus(10 * 365, ChronoUnit.DAYS)),
                key -> new JcaContentSignerBuilder("SHA256withECDSA").build(key));
    }

    private static CertificateStamp randomLeafStamp() {
        Instant now = Instant.now();
        return new CertificateStamp(
                serialNumber(),
                Date.from(now.minus(1, ChronoUnit.HOURS)),
                Date.from(now.plus(2 * 365, ChronoUnit.DAYS)),
                key -> new JcaContentSignerBuilder("SHA256withECDSA").build(key));
    }

    private static CertificateStamp seededStamp(String seed, String name) {
        return new CertificateStamp(
                new BigInteger(1, hkdf(seed, name + "/serial", 8)).add(BigInteger.ONE),
                Date.from(SEEDED_NOT_BEFORE),
                Date.from(SEEDED_NOT_AFTER),
                SimulatorPki::deterministicEcdsaSigner);
    }

    /**
     * A signer using deterministic ECDSA (RFC 6979), which on the wire is plain ecdsa-with-SHA256.
     * Built by hand because the operator API resolves signature names through a finder that does
     * not know the deterministic variant.
     */
    private static ContentSigner deterministicEcdsaSigner(PrivateKey signingKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withECDDSA", DETERMINISTIC_PROVIDER);
        signature.initSign(signingKey);
        ByteArrayOutputStream content = new ByteArrayOutputStream();
        return new ContentSigner() {
            @Override
            public AlgorithmIdentifier getAlgorithmIdentifier() {
                return new AlgorithmIdentifier(X9ObjectIdentifiers.ecdsa_with_SHA256);
            }

            @Override
            public OutputStream getOutputStream() {
                return content;
            }

            @Override
            public byte[] getSignature() {
                try {
                    signature.update(content.toByteArray());
                    return signature.sign();
                } catch (Exception e) {
                    throw new IllegalStateException("Deterministic signing failed", e);
                }
            }
        };
    }

    // random serials, because certificates created within the same millisecond must not collide
    private static BigInteger serialNumber() {
        return new BigInteger(64, RANDOM).add(BigInteger.ONE);
    }

    private static X509Certificate selfSignedCa(KeyPair keyPair, CertificateStamp stamp) throws Exception {
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                CA_NAME, stamp.serial(), stamp.notBefore(), stamp.notAfter(), CA_NAME, keyPair.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();
        builder.addExtension(
                Extension.subjectKeyIdentifier, false, extensionUtils.createSubjectKeyIdentifier(keyPair.getPublic()));
        return new JcaX509CertificateConverter()
                .getCertificate(builder.build(stamp.signer().create(keyPair.getPrivate())));
    }

    private static X509Certificate leafCertificate(
            X500Name subject,
            KeyPair leafKeyPair,
            KeyPair caKeyPair,
            X509Certificate caCertificate,
            CertificateStamp stamp)
            throws Exception {
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                new X500Name(caCertificate.getSubjectX500Principal().getName()),
                stamp.serial(),
                stamp.notBefore(),
                stamp.notAfter(),
                subject,
                leafKeyPair.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();
        builder.addExtension(
                Extension.subjectKeyIdentifier,
                false,
                extensionUtils.createSubjectKeyIdentifier(leafKeyPair.getPublic()));
        builder.addExtension(
                Extension.authorityKeyIdentifier,
                false,
                extensionUtils.createAuthorityKeyIdentifier(caKeyPair.getPublic()));
        return new JcaX509CertificateConverter()
                .getCertificate(builder.build(stamp.signer().create(caKeyPair.getPrivate())));
    }
}
