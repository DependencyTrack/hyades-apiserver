package org.dependencytrack.event.kafka.processor;

import alpine.Config;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.junit.Test;

import java.util.List;

public class KafkaProcessorManagerTest {

    public static class TestHandler {

        @KafkaRecordHandler(name = "foo", topics = "bar")
        public List<ProducerRecord<String, String>> foo(final List<ConsumerRecord<String, String>> bar) {
            return null;
        }

    }

    @Test
    public void foo() {
        final var manager = new KafkaProcessorManager(Config.getInstance());
        manager.registerHandler(new TestHandler());
    }

}