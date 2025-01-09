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
package org.dependencytrack.util;

import alpine.Config;
import alpine.event.framework.Subscriber;
import com.asahaf.javacron.InvalidExpressionException;
import com.asahaf.javacron.Schedule;
import com.google.common.base.CaseFormat;
import net.javacrumbs.shedlock.core.LockConfiguration;

import java.time.Duration;
import java.time.Instant;
import java.util.NoSuchElementException;

import static java.util.Objects.requireNonNull;

/**
 * @since 5.6.0
 */
public final class TaskUtil {

    private static final String PROPERTY_CRON = "cron";
    private static final String PROPERTY_LOCK_MAX_DURATION = "lock.max.duration";
    private static final String PROPERTY_LOCK_MIN_DURATION = "lock.min.duration";

    private TaskUtil() {
    }

    public static LockConfiguration getLockConfigForTask(final Class<? extends Subscriber> taskClass) {
        final String taskName = getTaskConfigName(taskClass);

        final String maxLockDurationString = Config.getInstance().getProperty(new TaskConfigKey(taskName, PROPERTY_LOCK_MAX_DURATION));
        if (maxLockDurationString == null) {
            throw new NoSuchElementException("No max lock duration configured for task %s".formatted(taskName));
        }

        final String minLockDurationString = Config.getInstance().getProperty(new TaskConfigKey(taskName, PROPERTY_LOCK_MIN_DURATION));
        if (minLockDurationString == null) {
            throw new NoSuchElementException("No min lock duration configured for task %s".formatted(taskName));
        }

        return new LockConfiguration(
                Instant.now(),
                taskName,
                Duration.parse(maxLockDurationString),
                Duration.parse(minLockDurationString));
    }

    public static Schedule getCronScheduleForTask(final Class<? extends Subscriber> taskClass) {
        final String taskName = getTaskConfigName(taskClass);

        final String cronExpression = Config.getInstance().getProperty(new TaskConfigKey(taskName, PROPERTY_CRON));
        if (cronExpression == null) {
            throw new NoSuchElementException("No cron expression configured for task %s".formatted(taskName));
        }

        try {
            return Schedule.create(cronExpression);
        } catch (InvalidExpressionException e) {
            throw new IllegalStateException("Failed to create schedule for task %s from cron expression %s".formatted(taskName, cronExpression), e);
        }
    }

    private static String getTaskConfigName(final Class<? extends Subscriber> taskClass) {
        requireNonNull(taskClass);

        // e.g. SomeFancyTask -> some.fancy
        return CaseFormat.UPPER_CAMEL.to(CaseFormat.LOWER_UNDERSCORE, taskClass.getSimpleName())
                .replaceAll("_", ".")
                .replaceAll("\\.task$", "");
    }

    private record TaskConfigKey(String taskName, String property) implements Config.Key {

        @Override
        public String getPropertyName() {
            return "task.%s.%s".formatted(taskName, property);
        }

        @Override
        public Object getDefaultValue() {
            return null;
        }

    }

}
