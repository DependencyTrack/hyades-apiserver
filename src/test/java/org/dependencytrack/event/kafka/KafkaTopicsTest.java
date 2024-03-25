package org.dependencytrack.event.kafka;

import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.EnvironmentVariables;

import static org.assertj.core.api.Assertions.assertThat;

public class KafkaTopicsTest {

    @Rule
    public final EnvironmentVariables environmentVariables = new EnvironmentVariables();

    @Test
    public void testTopicNameWithPrefix() {
        environmentVariables.set("KAFKA_TOPIC_PREFIX", "foo-bar.baz.");
        assertThat(KafkaTopics.VULN_ANALYSIS_RESULT.name()).isEqualTo("foo-bar.baz.dtrack.vuln-analysis.result");
    }

    @Test
    public void testTopicNameWithoutPrefix() {
        assertThat(KafkaTopics.VULN_ANALYSIS_RESULT.name()).isEqualTo("dtrack.vuln-analysis.result");
    }

}