package de.arbeitsagentur.opdt.walletsim.pki;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.stereotype.Component;

/**
 * Generated-at-startup PKI for the simulator: a self-signed P-256 CA (the trust anchor published
 * via the trust lists), a credential issuer leaf, and the holder binding key. All in-memory; a
 * restart creates a fresh PKI, matching the in-memory credential store.
 */
@Component
public class SimulatorPki {

    private static final X500Name CA_NAME = new X500Name("CN=EUDI Wallet Simulator CA,O=EUDI Wallet Simulator");
    private static final X500Name ISSUER_NAME = new X500Name("CN=EUDI Wallet Simulator Issuer,O=EUDI Wallet Simulator");

    private final KeyPair caKeyPair;
    private final X509Certificate caCertificate;
    private final KeyPair issuerKeyPair;
    private final X509Certificate issuerCertificate;
    private final ECKey holderKey;

    public SimulatorPki() {
        try {
            this.caKeyPair = generateP256KeyPair();
            this.caCertificate = selfSignedCa(caKeyPair);
            this.issuerKeyPair = generateP256KeyPair();
            this.issuerCertificate = leafCertificate(ISSUER_NAME, issuerKeyPair, caKeyPair, caCertificate);
            KeyPair holderKeyPair = generateP256KeyPair();
            this.holderKey = new ECKey.Builder(Curve.P_256, (ECPublicKey) holderKeyPair.getPublic())
                    .privateKey(holderKeyPair.getPrivate())
                    .build();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to generate simulator PKI", e);
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

    /** Holder key pair used for credential binding (cnf.jwk) and key-binding JWTs. */
    public ECKey holderKey() {
        return holderKey;
    }

    private static KeyPair generateP256KeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
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
