package de.arbeitsagentur.opdt.walletsim.oid4vp;

import static de.arbeitsagentur.opdt.walletsim.WalletTestSupport.issuerJwt;
import static org.assertj.core.api.Assertions.assertThat;

import de.arbeitsagentur.opdt.walletsim.WalletTestSupport;
import org.htmlunit.WebClient;
import org.htmlunit.html.DomElement;
import org.htmlunit.html.HtmlButton;
import org.htmlunit.html.HtmlCheckBoxInput;
import org.htmlunit.html.HtmlPage;
import org.htmlunit.html.HtmlRadioButtonInput;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * The show all toggle is client side behavior, so these tests execute the picker's JavaScript in
 * HtmlUnit. The rule under test: what the wallet presents is always on screen. Unpicked non
 * matching cards follow the toggle, a picked one stays visible, and moving the pick hides the
 * invalid card again.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ShowAllToggleUiTest {

    private static final String DCQL_QUERY =
            """
            {"credentials": [{
                "id": "pid",
                "format": "dc+sd-jwt",
                "meta": {"vct_values": ["urn:eudi:pid:1"]},
                "claims": [{"path": ["family_name"]}, {"path": ["given_name"]}]
            }]}
            """;

    private static final String UNSATISFIABLE_DCQL_QUERY =
            """
            {"credentials": [{
                "id": "pid",
                "format": "dc+sd-jwt",
                "meta": {"vct_values": ["urn:eudi:pid:1"]},
                "claims": [{"path": ["family_name"]}, {"path": ["shoe_size"]}]
            }]}
            """;

    @LocalServerPort
    private int port;

    @Test
    void unpickedNonMatchingCardsFollowTheToggle() throws Exception {
        try (TestVerifier verifier = new TestVerifier(DCQL_QUERY);
                WebClient client = newClient()) {
            HtmlPage page = client.getPage(
                    WalletTestSupport.authorizeUri(port, verifier).toURL());
            DomElement invalidCard = cardOf(page, "select-pid-ehic-erika-mustermann");
            assertThat(invalidCard.hasAttribute("hidden"))
                    .as("non matching cards start hidden")
                    .isTrue();

            toggle(page).click();
            assertThat(invalidCard.hasAttribute("hidden")).isFalse();

            toggle(page).click();
            assertThat(invalidCard.hasAttribute("hidden"))
                    .as("an unpicked card hides again")
                    .isTrue();
        }
    }

    @Test
    void pickedNonMatchingCardStaysVisibleAndIsPresented() throws Exception {
        try (TestVerifier verifier = new TestVerifier(DCQL_QUERY);
                WebClient client = newClient()) {
            HtmlPage page = client.getPage(
                    WalletTestSupport.authorizeUri(port, verifier).toURL());
            toggle(page).click();
            radio(page, "select-pid-ehic-erika-mustermann").click();
            toggle(page).click();

            DomElement invalidCard = cardOf(page, "select-pid-ehic-erika-mustermann");
            assertThat(invalidCard.hasAttribute("hidden"))
                    .as("the picked card stays visible, what is presented is on screen")
                    .isFalse();
            assertThat(radio(page, "select-pid-ehic-erika-mustermann").isChecked())
                    .isTrue();

            present(page);
            assertThat(issuerJwt(presentation(verifier, "pid"))
                            .getJWTClaimsSet()
                            .getStringClaim("vct"))
                    .as("the visible pick is what the verifier receives")
                    .isEqualTo("urn:eudi:ehic:1");
        }
    }

    @Test
    void movingThePickAfterTheToggleTurnedOffHidesTheInvalidCardAndPresentsTheNewPick() throws Exception {
        try (TestVerifier verifier = new TestVerifier(DCQL_QUERY);
                WebClient client = newClient()) {
            HtmlPage page = client.getPage(
                    WalletTestSupport.authorizeUri(port, verifier).toURL());
            toggle(page).click();
            radio(page, "select-pid-ehic-erika-mustermann").click();
            toggle(page).click();

            radio(page, "select-pid-pid-thomas-bauer").click();
            assertThat(cardOf(page, "select-pid-ehic-erika-mustermann").hasAttribute("hidden"))
                    .as("the invalid card hides once the pick moved away")
                    .isTrue();
            assertThat(radio(page, "select-pid-ehic-erika-mustermann").isChecked())
                    .isFalse();

            present(page);
            assertThat(issuerJwt(presentation(verifier, "pid"))
                            .getJWTClaimsSet()
                            .getStringClaim("vct"))
                    .as("the verifier receives the new pick, not the hidden one")
                    .isEqualTo("urn:eudi:pid:de:1");
        }
    }

    @Test
    void unsatisfiableQueryIsPresentableThroughTheToggleAndKeepsItsPickAcrossARoundTrip() throws Exception {
        try (TestVerifier verifier = new TestVerifier(UNSATISFIABLE_DCQL_QUERY);
                WebClient client = newClient()) {
            HtmlPage page = client.getPage(
                    WalletTestSupport.authorizeUri(port, verifier).toURL());
            assertThat(presentButton(page).isDisabled())
                    .as("nothing matches, so nothing can be presented")
                    .isTrue();

            toggle(page).click();
            assertThat(presentButton(page).isDisabled()).isFalse();
            assertThat(radio(page, "select-pid-pid-jan-hart").isChecked())
                    .as("a slot without a pick gets its first card")
                    .isTrue();

            toggle(page).click();
            assertThat(cardOf(page, "select-pid-pid-jan-hart").hasAttribute("hidden"))
                    .as("the picked card survives the toggle round trip")
                    .isFalse();
            toggle(page).click();
            assertThat(radio(page, "select-pid-pid-jan-hart").isChecked()).isTrue();

            present(page);
            assertThat(presentation(verifier, "pid"))
                    .as("the partial answer reaches the verifier")
                    .isNotEmpty();
        }
    }

    private static WebClient newClient() {
        WebClient client = new WebClient();
        // the submitted response is asserted at the test verifier, not by following its redirect
        client.getOptions().setRedirectEnabled(false);
        client.getOptions().setThrowExceptionOnFailingStatusCode(false);
        // the bundled bootstrap script is not under test and only needs to not break the page
        client.getOptions().setThrowExceptionOnScriptError(false);
        client.getOptions().setCssEnabled(false);
        return client;
    }

    private static HtmlCheckBoxInput toggle(HtmlPage page) {
        return page.getHtmlElementById("show-all-credentials");
    }

    private static HtmlRadioButtonInput radio(HtmlPage page, String id) {
        return page.getHtmlElementById(id);
    }

    private static HtmlButton presentButton(HtmlPage page) {
        return page.getHtmlElementById("present-credential");
    }

    private static void present(HtmlPage page) throws Exception {
        presentButton(page).click();
    }

    // the card column around a credential's radio button, which the toggle hides and reveals
    private static DomElement cardOf(HtmlPage page, String radioId) {
        DomElement card = page.getFirstByXPath("//div[@class='col'][.//input[@id='" + radioId + "']]");
        assertThat(card).as("card of %s", radioId).isNotNull();
        return card;
    }

    private static String presentation(TestVerifier verifier, String queryId) throws Exception {
        JsonNode vpToken = new ObjectMapper()
                .readValue(verifier.awaitResponse().formParameters().get("vp_token"), JsonNode.class);
        return vpToken.get(queryId).get(0).asText();
    }
}
