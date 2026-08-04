package de.arbeitsagentur.opdt.walletsim.pki;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The PKI must survive restarts so trust lists and registration certificates issued before a
 * restart remain valid: a second instance over the same directory loads identical material.
 */
class PkiPersistenceTest {

    @TempDir
    Path pkiDir;

    @Test
    void reloadsIdenticalKeysAndCertificatesFromDisk() throws Exception {
        SimulatorPki first = new SimulatorPki(pkiDir);
        SimulatorPki second = new SimulatorPki(pkiDir);

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
    }
}
