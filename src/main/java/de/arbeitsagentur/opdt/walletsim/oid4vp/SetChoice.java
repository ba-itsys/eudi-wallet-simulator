package de.arbeitsagentur.opdt.walletsim.oid4vp;

import java.util.List;

// A credential set the user answers by choosing one of its options in the picker.
public record SetChoice(int index, boolean required, List<SetOption> options) {

    // the form value of the skip entry in the picker dropdown
    public static final String SKIP_OPTION = "skip";

    /**
     * The option the picker preselects and the submit assumes when the form carries no value:
     * the first satisfiable option. Without one, an optional set defaults to skip, so requests
     * are answered the same way as before unsatisfiable options became choosable. A required set
     * falls back to its first option.
     */
    public String defaultValue() {
        return options.stream()
                .filter(SetOption::satisfiable)
                .findFirst()
                .map(option -> String.valueOf(option.index()))
                .orElse(required ? "0" : SKIP_OPTION);
    }
}
