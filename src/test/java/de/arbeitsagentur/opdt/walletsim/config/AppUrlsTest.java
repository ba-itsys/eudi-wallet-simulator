package de.arbeitsagentur.opdt.walletsim.config;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class AppUrlsTest {

    @Test
    void trailingSlashIsStrippedSoDerivedUrlsStayValid() {
        AppUrls urls = new AppUrls("http://localhost:8080/");

        assertThat(urls.baseUrl()).isEqualTo("http://localhost:8080");
        assertThat(urls.statusListUri()).isEqualTo("http://localhost:8080/status-list");
    }
}
