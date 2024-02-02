package org.dependencytrack.event.kafka.processor.api;

import io.confluent.parallelconsumer.ParallelConsumerOptions.ProcessingOrder;

final class ProcessorProperties {

    static final String PROPERTY_MAX_BATCH_SIZE = "max.batch.size";
    static final int PROPERTY_MAX_BATCH_SIZE_DEFAULT = 10;
    static final String PROPERTY_MAX_CONCURRENCY = "max.concurrency";
    static final int PROPERTY_MAX_CONCURRENCY_DEFAULT = 1;
    static final String PROPERTY_PROCESSING_ORDER = "processing.order";
    static final ProcessingOrder PROPERTY_PROCESSING_ORDER_DEFAULT = ProcessingOrder.PARTITION;
    static final String PROPERTY_RETRY_INITIAL_DELAY_MS = "retry.initial.delay.ms";
    static final long PROPERTY_RETRY_INITIAL_DELAY_MS_DEFAULT = 1000; // 1s
    static final String PROPERTY_RETRY_MULTIPLIER = "retry.multiplier";
    static final int PROPERTY_RETRY_MULTIPLIER_DEFAULT = 1;
    static final String PROPERTY_RETRY_RANDOMIZATION_FACTOR = "retry.randomization.factor";
    static final double PROPERTY_RETRY_RANDOMIZATION_FACTOR_DEFAULT = 0.3;
    static final String PROPERTY_RETRY_MAX_DELAY_MS = "retry.max.delay.ms";
    static final long PROPERTY_RETRY_MAX_DELAY_MS_DEFAULT = 60 * 1000; // 60s

    private ProcessorProperties() {
    }

}
