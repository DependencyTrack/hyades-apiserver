package org.dependencytrack.common;

/**
 * Common fields for use with SLF4J's {@link org.slf4j.MDC}.
 */
public final class MdcKeys {

    public static final String MDC_KAFKA_RECORD_TOPIC = "kafkaRecordTopic";
    public static final String MDC_KAFKA_RECORD_PARTITION = "kafkaRecordPartition";
    public static final String MDC_KAFKA_RECORD_OFFSET = "kafkaRecordOffset";
    public static final String MDC_KAFKA_RECORD_KEY = "kafkaRecordKey";

    private MdcKeys() {
    }

}
