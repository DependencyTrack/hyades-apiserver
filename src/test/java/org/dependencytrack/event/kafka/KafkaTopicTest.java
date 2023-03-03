package org.dependencytrack.event.kafka;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class KafkaTopicTest {

    @Test
    public void testKafkaTopicConfig() {
        System.setProperty("api.topic.prefix", "customPrefix.");
        assertEquals("customPrefix.dtrack.vulnerability.mirror.osv", KafkaTopic.MIRROR_OSV.getName());
        System.clearProperty("api.topic.prefix");
        assertEquals("dtrack.vulnerability.mirror.osv", KafkaTopic.MIRROR_OSV.getName());
    }
}
