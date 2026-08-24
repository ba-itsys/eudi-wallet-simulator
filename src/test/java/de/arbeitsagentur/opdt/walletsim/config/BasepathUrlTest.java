package de.arbeitsagentur.opdt.walletsim.config;

import static de.arbeitsagentur.opdt.walletsim.WalletTestSupport.issuerJwt;
import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.opdt.walletsim.conformance.ValidationMode;
import de.arbeitsagentur.opdt.walletsim.credentials.CredentialStore;
import de.arbeitsagentur.opdt.walletsim.credentials.StoredCredential;
import de.arbeitsagentur.opdt.walletsim.statuslist.StatusListService;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * Behind a path rewriting ingress the simulator is reachable under base URL plus basepath, so
 * every URL embedded into issued tokens has to carry that prefix.
 */
@SpringBootTest(properties = {"app.base-url=https://example.com", "app.basepath=/my/wallet"})
class BasepathUrlTest {

    @Autowired
    private CredentialStore credentialStore;

    @Autowired
    private StatusListService statusListService;

    @Test
    void issuedCredentialCarriesBasepathInStatusListUriAndIssuer() throws Exception {
        List<StoredCredential> credentials = credentialStore.findAll();
        assertThat(credentials).as("pre-defined credentials seeded from YAML").isNotEmpty();

        SignedJWT issuerJwt = issuerJwt(credentials.getFirst().sdJwt());
        JWTClaimsSet claims = issuerJwt.getJWTClaimsSet();

        assertThat(claims.getIssuer()).isEqualTo("https://example.com/my/wallet");
        Map<String, Object> status = asMap(claims.getClaim("status"));
        Map<String, Object> statusList = asMap(status.get("status_list"));
        assertThat(statusList.get("uri")).isEqualTo("https://example.com/my/wallet/api/status-list");
    }

    @Test
    void statusListTokenSubjectMatchesTheUriInsideCredentials() throws Exception {
        JWTClaimsSet claims = SignedJWT.parse(statusListService.statusListJwt()).getJWTClaimsSet();

        assertThat(claims.getSubject()).isEqualTo("https://example.com/my/wallet/api/status-list");
        assertThat(claims.getIssuer()).isEqualTo("https://example.com/my/wallet");
    }

    @Test
    void basepathIsNormalizedToLeadingSlashWithoutTrailingSlash() {
        AppProperties properties = new AppProperties("https://example.com/", "my/wallet/", ValidationMode.DEBUG, false);

        assertThat(properties.externalUrl()).isEqualTo("https://example.com/my/wallet");
        assertThat(properties.statusListUri()).isEqualTo("https://example.com/my/wallet/api/status-list");
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asMap(Object value) {
        assertThat(value).isInstanceOf(Map.class);
        return (Map<String, Object>) value;
    }
}
