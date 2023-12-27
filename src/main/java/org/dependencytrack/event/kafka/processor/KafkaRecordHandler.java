package org.dependencytrack.event.kafka.processor;

import io.confluent.parallelconsumer.ParallelConsumerOptions.ProcessingOrder;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
public @interface KafkaRecordHandler {

    String name();

    String[] topics();

    ProcessingOrder ordering() default ProcessingOrder.KEY;

    int maxBatchSize() default 1;

    int maxConcurrency() default 1;

}
