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
package org.dependencytrack.workflow.api;

import org.jspecify.annotations.Nullable;

import static java.util.Objects.requireNonNull;

/**
 * @param queueName   Name of the queue in which the call should be added.
 * @param argument    Argument of the call.
 * @param retryPolicy Retry policy of the call.
 * @param <A>
 */
public record ActivityCallOptions<A extends @Nullable Object>(
        String queueName,
        @Nullable A argument,
        RetryPolicy retryPolicy) {

    public ActivityCallOptions {
        requireNonNull(queueName, "queueName must not be null");
        requireNonNull(retryPolicy, "retryPolicy must not be null");
    }

    public ActivityCallOptions() {
        this("default", null, RetryPolicy.defaultRetryPolicy());
    }

    public ActivityCallOptions<A> withQueueName(final String queueName) {
        return new ActivityCallOptions<>(queueName, this.argument, this.retryPolicy);
    }

    public ActivityCallOptions<A> withArgument(final @Nullable A argument) {
        return new ActivityCallOptions<>(this.queueName, argument, this.retryPolicy);
    }

    public ActivityCallOptions<A> withRetryPolicy(final RetryPolicy retryPolicy) {
        return new ActivityCallOptions<>(this.queueName, this.argument, retryPolicy);
    }

}
