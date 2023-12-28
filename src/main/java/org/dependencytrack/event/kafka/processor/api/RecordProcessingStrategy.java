package org.dependencytrack.event.kafka.processor.api;

import io.confluent.parallelconsumer.ParallelStreamProcessor;

public interface RecordProcessingStrategy {

    /**
     * Process records provided by a given {@link ParallelStreamProcessor}.
     *
     * @param streamProcessor The {@link ParallelStreamProcessor} to process records from
     */
    void process(final ParallelStreamProcessor<byte[], byte[]> streamProcessor);

}
