package de.arbeitsagentur.opdt.walletsim.logging;

import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Component;

/** In-memory activity log of protocol interactions, capped to the most recent entries. */
@Component
public class ActivityLog {

    public enum Severity {
        SUCCESS,
        WARNING,
        ERROR
    }

    public record Entry(
            Instant timestamp, String category, Severity severity, String message, Map<String, Object> details) {}

    private static final int MAX_ENTRIES = 1000;

    private final Deque<Entry> entries = new ArrayDeque<>();

    public synchronized void success(String category, String message, Map<String, Object> details) {
        add(new Entry(Instant.now(), category, Severity.SUCCESS, message, details));
    }

    public synchronized void warning(String category, String message, Map<String, Object> details) {
        add(new Entry(Instant.now(), category, Severity.WARNING, message, details));
    }

    public synchronized void error(String category, String message, Map<String, Object> details) {
        add(new Entry(Instant.now(), category, Severity.ERROR, message, details));
    }

    public synchronized List<Entry> entries() {
        return List.copyOf(entries);
    }

    public synchronized void clear() {
        entries.clear();
    }

    private void add(Entry entry) {
        if (entries.size() >= MAX_ENTRIES) {
            entries.removeLast();
        }
        entries.addFirst(entry);
    }
}
