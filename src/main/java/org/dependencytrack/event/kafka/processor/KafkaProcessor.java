package org.dependencytrack.event.kafka.processor;

import io.confluent.parallelconsumer.ParallelStreamProcessor;
import org.dependencytrack.event.kafka.processor.api.RecordProcessingStrategy;

public class KafkaProcessor implements AutoCloseable {

    private final ParallelStreamProcessor<byte[], byte[]> streamProcessor;
    private final RecordProcessingStrategy processingStrategy;

    KafkaProcessor(final ParallelStreamProcessor<byte[], byte[]> streamProcessor,
                   final RecordProcessingStrategy processingStrategy) {
        this.streamProcessor = streamProcessor;
        this.processingStrategy = processingStrategy;
    }

    public void start() {
        // TODO: Ensure streamProcessor is subscribed to at least one topic.
        processingStrategy.process(streamProcessor);
    }

    @Override
    public void close() {
        // TODO: Drain timeout should be configurable.
        streamProcessor.closeDrainFirst();
    }

}
