package de.arbeitsagentur.opdt.walletsim.oid4vp;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * The simplified urn child rule: a child type inserts segments between the base prefix and the
 * trailing version segment. Non urn types match exactly.
 */
class VctMatcherTest {

    @Test
    void urnChildrenExtendTheirBaseType() {
        assertThat(VctMatcher.matches(List.of("urn:eudi:pid:1"), "urn:eudi:pid:de:1"))
                .isTrue();
        assertThat(VctMatcher.matches(List.of("urn:eudi:pid:1"), "urn:eudi:pid:de:bavaria:1"))
                .isTrue();
        assertThat(VctMatcher.matches(List.of("urn:eudi:pid:1"), "urn:eudi:pid:1"))
                .isTrue();
    }

    @Test
    void baseTypesAndSiblingsDoNotExtendEachOther() {
        assertThat(VctMatcher.matches(List.of("urn:eudi:pid:de:1"), "urn:eudi:pid:1"))
                .isFalse();
        assertThat(VctMatcher.matches(List.of("urn:eudi:pid:de:1"), "urn:eudi:pid:it:1"))
                .isFalse();
    }

    @Test
    void versionMustMatch() {
        assertThat(VctMatcher.matches(List.of("urn:eudi:pid:2"), "urn:eudi:pid:de:1"))
                .isFalse();
        assertThat(VctMatcher.matches(List.of("urn:eudi:pid:1"), "urn:eudi:diploma:de:1"))
                .isFalse();
    }

    @Test
    void nonUrnTypesMatchExactlyOnly() {
        assertThat(VctMatcher.matches(List.of("https://example.com/pid"), "https://example.com/pid"))
                .isTrue();
        assertThat(VctMatcher.matches(List.of("https://example.com/pid"), "https://example.com/pid/de"))
                .isFalse();
        assertThat(VctMatcher.matches(List.of("urn:eudi:pid:1"), "https://example.com/pid"))
                .isFalse();
    }

    @Test
    void emptyVctValuesMatchEverything() {
        assertThat(VctMatcher.matches(List.of(), "anything")).isTrue();
    }
}
