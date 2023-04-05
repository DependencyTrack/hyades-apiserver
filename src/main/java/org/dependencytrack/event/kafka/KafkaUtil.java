package org.dependencytrack.event.kafka;

import org.apache.kafka.common.header.Header;
import org.apache.kafka.common.header.Headers;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

public final class KafkaUtil {

    private KafkaUtil() {
    }

    public static Optional<String> getEventHeader(final Headers headers, final String name) {
        final Header header = headers.lastHeader(name);
        if (header != null && header.value() != null) {
            return Optional.of(header.value())
                    .map(value -> new String(value, StandardCharsets.UTF_8));
        }

        return Optional.empty();
    }

}
