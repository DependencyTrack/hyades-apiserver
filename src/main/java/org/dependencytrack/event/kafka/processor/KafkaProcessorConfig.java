package org.dependencytrack.event.kafka.processor;

import io.confluent.parallelconsumer.ParallelConsumerOptions.ProcessingOrder;

import java.lang.reflect.Method;
import java.util.Collection;

public class KafkaProcessorConfig {

    private String name;
    private Collection<String> topics;
    private Object handlerInstance;
    private Method handlerMethod;
    private ProcessingOrder ordering;
    private int maxBatchSize;
    private int maxConcurrency;

    public String name() {
        return name;
    }

    public KafkaProcessorConfig setName(String name) {
        this.name = name;
        return this;
    }

    public Collection<String> topics() {
        return topics;
    }

    public KafkaProcessorConfig setTopics(Collection<String> topics) {
        this.topics = topics;
        return this;
    }

    public Object handlerInstance() {
        return handlerInstance;
    }

    public KafkaProcessorConfig setHandlerInstance(Object handlerInstance) {
        this.handlerInstance = handlerInstance;
        return this;
    }

    public Method handlerMethod() {
        return handlerMethod;
    }

    public KafkaProcessorConfig setHandlerMethod(Method handlerMethod) {
        this.handlerMethod = handlerMethod;
        return this;
    }

    public ProcessingOrder ordering() {
        return ordering;
    }

    public KafkaProcessorConfig setOrdering(ProcessingOrder ordering) {
        this.ordering = ordering;
        return this;
    }

    public int maxBatchSize() {
        return maxBatchSize;
    }

    public KafkaProcessorConfig setMaxBatchSize(int maxBatchSize) {
        this.maxBatchSize = maxBatchSize;
        return this;
    }

    public int maxConcurrency() {
        return maxConcurrency;
    }

    public KafkaProcessorConfig setMaxConcurrency(int maxConcurrency) {
        this.maxConcurrency = maxConcurrency;
        return this;
    }

    public boolean isBatch() {
        return maxBatchSize > 1;
    }

}
