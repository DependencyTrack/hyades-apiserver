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

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class BufferTest {

    @Test
    void shouldFlushAtInterval() throws Exception {
        final var flushedItems = new ArrayList<String>();

        final var buffer = new Buffer<@NonNull String>(
                "test",
                flushedItems::addAll,
                Duration.ofMillis(100),
                /* maxBatchSize */ 10,
                new SimpleMeterRegistry());

        try (buffer) {
            buffer.start();

            final CompletableFuture<Void> future = buffer.add("foo");
            future.get(500, TimeUnit.MILLISECONDS);

            assertThat(flushedItems).containsOnly("foo");
        }
    }

    @Test
    void addShouldThrowWhenNotRunning() {
        final Consumer<List<String>> batchConsumer = ignored -> {
        };

        final var buffer = new Buffer<>(
                "test",
                batchConsumer,
                Duration.ZERO,
                /* maxBatchSize */ 10,
                new SimpleMeterRegistry());

        try (buffer) {
            assertThatExceptionOfType(IllegalStateException.class)
                    .isThrownBy(() -> buffer.add("foo"))
                    .withMessage("Cannot accept new items in current status: CREATED");
        }
    }

    @Test
    void addShouldFlushWhenMaxBatchSizeIsReached() throws Exception {
        final var flushedBatches = new ArrayBlockingQueue<List<String>>(5);

        final var buffer = new Buffer<>(
                "test",
                flushedBatches::add,
                Duration.ofMillis(50),
                /* maxBatchSize */ 2,
                Duration.ofSeconds(5),
                new SimpleMeterRegistry());

        try (buffer) {
            buffer.start();

            buffer.add("foo");
            buffer.add("bar");
            buffer.add("baz");

            assertThat(flushedBatches).containsExactly(List.of("foo", "bar"));
            // baz remains queued until flush interval elapses.
        }
    }

}