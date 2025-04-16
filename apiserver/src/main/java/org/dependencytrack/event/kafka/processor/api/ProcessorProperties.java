/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
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
    static final String PROPERTY_SHUTDOWN_TIMEOUT_MS = "shutdown.timeout.ms";
    static final long PROPERTY_SHUTDOWN_TIMEOUT_MS_DEFAULT = 10 * 1000; // 10s

    private ProcessorProperties() {
    }

}
