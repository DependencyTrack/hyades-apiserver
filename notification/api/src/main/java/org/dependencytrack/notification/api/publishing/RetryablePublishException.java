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
package org.dependencytrack.notification.api.publishing;

import org.jspecify.annotations.Nullable;

import java.time.Duration;

/**
 * Exception for publish failures that may be retried.
 *
 * @since 5.7.0
 */
public class RetryablePublishException extends RuntimeException {

    private final @Nullable Duration retryAfter;

    public RetryablePublishException(
            @Nullable String message,
            @Nullable Throwable cause,
            @Nullable Duration retryAfter) {
        super(message, cause);
        this.retryAfter = retryAfter;
    }

    public RetryablePublishException(@Nullable String message, @Nullable Throwable cause) {
        this(message, cause, null);
    }

    public RetryablePublishException(@Nullable String message, @Nullable Duration retryAfter) {
        this(message, null, retryAfter);
    }

    public RetryablePublishException(@Nullable String message) {
        this(message, null, null);
    }

    public @Nullable Duration getRetryAfter() {
        return retryAfter;
    }

}
