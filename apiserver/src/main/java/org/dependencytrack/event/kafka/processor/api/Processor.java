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

/**
 * A processor of individual {@link ConsumerRecord}s.
 *
 * @param <K> Type of the {@link ConsumerRecord} key
 * @param <V> Type of the {@link ConsumerRecord} value
 */
public interface Processor<K, V> {

    /**
     * Process a {@link ConsumerRecord}.
     * <p>
     * This method may be called by multiple threads concurrently and thus MUST be thread safe!
     *
     * @param record The {@link ConsumerRecord} to process
     * @throws ProcessingException When processing the {@link ConsumerRecord} failed
     */
    void process(final ConsumerRecord<K, V> record) throws ProcessingException;

}
