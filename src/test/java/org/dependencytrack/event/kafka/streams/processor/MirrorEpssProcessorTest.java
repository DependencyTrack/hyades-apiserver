package org.dependencytrack.event.kafka.streams.processor;

import org.apache.kafka.common.serialization.Serdes;
import org.apache.kafka.common.serialization.StringSerializer;
import org.apache.kafka.streams.StreamsBuilder;
import org.apache.kafka.streams.TestInputTopic;
import org.apache.kafka.streams.TopologyTestDriver;
import org.apache.kafka.streams.kstream.Consumed;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.event.kafka.serialization.KafkaProtobufSerde;
import org.dependencytrack.event.kafka.serialization.KafkaProtobufSerializer;
import org.dependencytrack.proto.mirror.v1.EpssItem;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class MirrorEpssProcessorTest extends PersistenceCapableTest {

    private TopologyTestDriver testDriver;
    private TestInputTopic<String, EpssItem> inputTopic;

    @Before
    public void setUp() throws Exception {
        final var streamsBuilder = new StreamsBuilder();
        streamsBuilder
                .stream("input-topic", Consumed
                        .with(Serdes.String(), new KafkaProtobufSerde<>(EpssItem.parser())))
                .process(MirrorEpssProcessor::new);
        testDriver = new TopologyTestDriver(streamsBuilder.build());
        inputTopic = testDriver.createInputTopic("input-topic",
                new StringSerializer(), new KafkaProtobufSerializer<>());
    }

    @After
    public void tearDown() {
        if (testDriver != null) {
            testDriver.close();
        }
    }

    @Test
    public void testProcessEpssRecord() {
        final var epssRecord = EpssItem.newBuilder()
                .setCve("CVE-333").setEpss(2.3).setPercentile(5.6).build();
        inputTopic.pipeInput("CVE-333", epssRecord);
        final var epss = qm.getEpssByCveId("CVE-333");
        assertThat(epss).isNotNull();
        assertThat(epss.getEpss()).isEqualByComparingTo("2.3");
        assertThat(epss.getPercentile()).isEqualByComparingTo("5.6");
    }

    @Test
    public void testProcessEpssRecordd() {
        inputTopic.pipeInput("CVE-333", null);
        final var epss = qm.getEpssByCveId("CVE-333");
        assertThat(epss).isNull();
    }
}
