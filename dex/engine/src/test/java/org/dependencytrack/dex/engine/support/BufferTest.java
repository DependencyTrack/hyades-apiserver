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
package org.dependencytrack.dex.engine.support;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeoutException;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class BufferTest {

    @Test
    void shouldFlushAtInterval() throws Exception {
        final var flushedItems = new ArrayList<String>();

        try (final var buffer = new Buffer<String>("test", flushedItems::addAll, Duration.ofMillis(100), 10, null)) {
            buffer.start();

            final CompletableFuture<Void> future = buffer.add("foo");
            future.join();

            assertThat(flushedItems).containsOnly("foo");
        }
    }

    @Test
    void addShouldThrowWhenNotRunning() {
        final Consumer<List<String>> batchConsumer = ignored -> {
        };

        try (final var buffer = new Buffer<>("test", batchConsumer, Duration.ZERO, 10, null)) {
            assertThatExceptionOfType(IllegalStateException.class)
                    .isThrownBy(() -> buffer.add("foo"))
                    .withMessage("Cannot accept new items in current status: CREATED");
        }
    }

    @Test
    void addShouldThrowWhenQueueTimesOut() throws Exception {
        final Consumer<List<String>> batchConsumer = ignored -> {
        };

        try (final var buffer = new Buffer<>("test", batchConsumer, Duration.ofSeconds(5), 1, Duration.ofMillis(10), null)) {
            buffer.start();

            buffer.add("foo");

            assertThatExceptionOfType(TimeoutException.class)
                    .isThrownBy(() -> buffer.add("bar"))
                    .withMessage("Timed out while waiting for buffer queue to accept the item");
        }
    }

}