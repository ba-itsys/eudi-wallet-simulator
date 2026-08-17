package de.arbeitsagentur.opdt.walletsim.pki;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * A configured seed must yield the same key and certificate material on every start without
 * touching the filesystem, so the simulator can run stateless on a read only filesystem and a
 * redeployed instance stays the PKI a verifier already trusts.
 */
class PkiSeedDerivationTest {

    @TempDir
    Path pkiDir;

    @Test
    void sameSeedDerivesByteIdenticalMaterialWithoutTouchingDisk() throws Exception {
        SimulatorPki first = new SimulatorPki(pkiDir, "test-seed");
        SimulatorPki second = new SimulatorPki(pkiDir, "test-seed");

        assertThat(second.caCertificate().getEncoded())
                .isEqualTo(first.caCertificate().getEncoded());
        assertThat(second.issuerCertificate().getEncoded())
                .isEqualTo(first.issuerCertificate().getEncoded());
        assertThat(second.registrarCertificate().getEncoded())
                .isEqualTo(first.registrarCertificate().getEncoded());
        assertThat(second.walletProviderCertificate().getEncoded())
                .isEqualTo(first.walletProviderCertificate().getEncoded());
        assertThat(second.registrarPrivateKey().getEncoded())
                .isEqualTo(first.registrarPrivateKey().getEncoded());
        assertThat(second.holderKey().toECPrivateKey().getEncoded())
                .isEqualTo(first.holderKey().toECPrivateKey().getEncoded());
        assertThat(Files.list(pkiDir))
                .as("a seeded PKI must not read or write files")
                .isEmpty();
    }

    @Test
    void differentSeedsDeriveDifferentKeys() throws Exception {
        SimulatorPki first = new SimulatorPki(pkiDir, "seed-one");
        SimulatorPki second = new SimulatorPki(pkiDir, "seed-two");

        assertThat(second.registrarPrivateKey().getEncoded())
                .isNotEqualTo(first.registrarPrivateKey().getEncoded());
        assertThat(second.caCertificate().getEncoded())
                .isNotEqualTo(first.caCertificate().getEncoded());
    }

    @Test
    void derivedKeysDifferPerName() throws Exception {
        SimulatorPki pki = new SimulatorPki(pkiDir, "test-seed");

        assertThat(List.of(
                        pki.caCertificate().getPublicKey(),
                        pki.issuerCertificate().getPublicKey(),
                        pki.walletProviderCertificate().getPublicKey(),
                        pki.registrarCertificate().getPublicKey(),
                        pki.holderKey().toECPublicKey()))
                .doesNotHaveDuplicates();
    }

    @Test
    void derivedCertificatesFormAValidChain() throws Exception {
        SimulatorPki pki = new SimulatorPki(pkiDir, "test-seed");

        pki.caCertificate().verify(pki.caCertificate().getPublicKey());
        pki.issuerCertificate().verify(pki.caCertificate().getPublicKey());
        pki.registrarCertificate().verify(pki.caCertificate().getPublicKey());
        pki.walletProviderCertificate().verify(pki.caCertificate().getPublicKey());
        pki.caCertificate().checkValidity();
        pki.issuerCertificate().checkValidity();

        assertThat(List.of(
                        pki.caCertificate().getSerialNumber(),
                        pki.issuerCertificate().getSerialNumber(),
                        pki.walletProviderCertificate().getSerialNumber(),
                        pki.registrarCertificate().getSerialNumber()))
                .doesNotHaveDuplicates();
    }
}
