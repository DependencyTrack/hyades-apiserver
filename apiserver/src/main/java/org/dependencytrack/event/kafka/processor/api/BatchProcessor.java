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

import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.dependencytrack.event.kafka.processor.exception.ProcessingException;

import java.util.List;

/**
 * A processor of {@link ConsumerRecord} batches.
 *
 * @param <K> Type of the {@link ConsumerRecord} key
 * @param <V> Type of the {@link ConsumerRecord} value
 */
public interface BatchProcessor<K, V> {

    /**
     * Process a batch of {@link ConsumerRecord}s.
     * <p>
     * This method may be called by multiple threads concurrently and thus MUST be thread safe!
     *
     * @param records Batch of {@link ConsumerRecord}s to process
     * @throws ProcessingException When consuming the batch of {@link ConsumerRecord}s failed
     */
    void process(final List<ConsumerRecord<K, V>> records) throws ProcessingException;

}
