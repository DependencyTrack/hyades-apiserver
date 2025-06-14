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
package org.dependencytrack.workflow.engine;

import com.google.protobuf.DebugFormat;
import org.dependencytrack.workflow.api.failure.ActivityFailureException;
import org.dependencytrack.workflow.api.failure.ApplicationFailureException;
import org.dependencytrack.workflow.api.failure.CancellationFailureException;
import org.dependencytrack.workflow.api.failure.SideEffectFailureException;
import org.dependencytrack.workflow.api.failure.SubWorkflowFailureException;
import org.dependencytrack.workflow.api.failure.WorkflowFailureException;
import org.dependencytrack.workflow.api.proto.v1.ActivityFailureDetails;
import org.dependencytrack.workflow.api.proto.v1.ApplicationFailureDetails;
import org.dependencytrack.workflow.api.proto.v1.CancellationFailureDetails;
import org.dependencytrack.workflow.api.proto.v1.SideEffectFailureDetails;
import org.dependencytrack.workflow.api.proto.v1.SubWorkflowFailureDetails;
import org.dependencytrack.workflow.api.proto.v1.WorkflowFailure;
import org.jspecify.annotations.Nullable;

import java.util.StringJoiner;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class FailureConverter {

    private FailureConverter() {
    }

    static WorkflowFailureException toException(final WorkflowFailure failure) {
        final WorkflowFailureException cause = failure.hasCause()
                ? toException(failure.getCause())
                : null;

        final WorkflowFailureException exception = switch (failure.getFailureDetailsCase()) {
            case ACTIVITY_FAILURE_DETAILS -> {
                final ActivityFailureDetails details = failure.getActivityFailureDetails();
                yield new ActivityFailureException(details.getActivityName(), cause);
            }
            case APPLICATION_FAILURE_DETAILS -> {
                final ApplicationFailureDetails details = failure.getApplicationFailureDetails();
                yield new ApplicationFailureException(failure.getMessage(), cause, details.getIsTerminal());
            }
            case CANCELLATION_FAILURE_DETAILS -> {
                final CancellationFailureDetails details = failure.getCancellationFailureDetails();
                yield new CancellationFailureException(details.getReason());
            }
            case SIDE_EFFECT_FAILURE_DETAILS -> {
                final SideEffectFailureDetails details = failure.getSideEffectFailureDetails();
                yield new SideEffectFailureException(details.getSideEffectName(), cause);
            }
            case SUB_WORKFLOW_FAILURE_DETAILS -> {
                final SubWorkflowFailureDetails details = failure.getSubWorkflowFailureDetails();
                yield new SubWorkflowFailureException(
                        UUID.fromString(details.getWorkflowRunId()),
                        details.getWorkflowName(),
                        details.getWorkflowVersion(),
                        cause);
            }
            default -> throw new IllegalArgumentException(
                    "Unknown details type %s for failure: %s".formatted(
                            failure.getFailureDetailsCase(),
                            DebugFormat.singleLine().toString(failure)));
        };

        if (failure.hasStackTrace()) {
            exception.setStackTrace(deserializeStackTrace(failure.getStackTrace()));
        }

        return exception;
    }

    static WorkflowFailure toFailure(final Throwable throwable) {
        final WorkflowFailure.Builder failureBuilder = WorkflowFailure.newBuilder();

        switch (throwable) {
            case final ActivityFailureException activityException -> failureBuilder
                    .setMessage(activityException.getOriginalMessage())
                    .setActivityFailureDetails(
                            ActivityFailureDetails.newBuilder()
                                    .setActivityName(activityException.getActivityName())
                                    .build());
            case final ApplicationFailureException applicationException -> failureBuilder
                    .setMessage(applicationException.getOriginalMessage())
                    .setApplicationFailureDetails(
                            ApplicationFailureDetails.newBuilder()
                                    .setIsTerminal(applicationException.isTerminal())
                                    .build());
            case final CancellationFailureException cancellationException -> failureBuilder
                    .setMessage(cancellationException.getOriginalMessage())
                    .setCancellationFailureDetails(
                            CancellationFailureDetails.newBuilder()
                                    .setReason(cancellationException.getReason())
                                    .build());
            case final SideEffectFailureException sideEffectException -> failureBuilder
                    .setSideEffectFailureDetails(
                            SideEffectFailureDetails.newBuilder()
                                    .setSideEffectName(sideEffectException.getSideEffectName())
                                    .build());
            case final SubWorkflowFailureException subWorkflowException -> failureBuilder
                    .setSubWorkflowFailureDetails(
                            SubWorkflowFailureDetails.newBuilder()
                                    .setWorkflowRunId(subWorkflowException.getRunId().toString())
                                    .setWorkflowName(subWorkflowException.getWorkflowName())
                                    .setWorkflowVersion(subWorkflowException.getWorkflowVersion())
                                    .build());
            default -> {
                if (throwable.getMessage() != null) {
                    failureBuilder.setMessage(throwable.getMessage());
                }

                failureBuilder.setApplicationFailureDetails(
                        ApplicationFailureDetails.newBuilder()
                                .setIsTerminal(false)
                                .build());
            }
        }

        if (throwable.getStackTrace() != null && throwable.getStackTrace().length > 0) {
            failureBuilder.setStackTrace(serializeStackTrace(throwable.getStackTrace()));
        }

        if (throwable.getCause() != null) {
            failureBuilder.setCause(toFailure(throwable.getCause()));
        }

        return failureBuilder.build();
    }

    @Nullable
    private static String serializeStackTrace(@Nullable final StackTraceElement[] stackTrace) {
        if (stackTrace == null || stackTrace.length == 0) {
            return null;
        }

        final var serializedStackTraceJoiner = new StringJoiner("\n");
        for (final StackTraceElement element : stackTrace) {
            // Cut the stack trace off before it enters engine internals.
            // These are not necessary for communicating failures in user code.
            if (element.getClassName().equals("org.dependencytrack.workflow.framework.ActivityTaskProcessor")
                || element.getClassName().equals("org.dependencytrack.workflow.framework.WorkflowTaskProcessor")) {
                break;
            }

            var serializedElement = "%s.%s".formatted(element.getClassName(), element.getMethodName());
            if (element.getFileName() != null) {
                serializedElement += "(%s:%d)".formatted(element.getFileName(), element.getLineNumber());
            }

            serializedStackTraceJoiner.add(serializedElement);
        }

        return serializedStackTraceJoiner.toString();
    }

    private static final Pattern STACK_TRACE_ELEMENT_PATTERN = Pattern.compile(
            "^(?<className>[\\w.$]+)\\.(?<methodName>[\\w.$]+)(?:\\((?<fileName>[\\w.]+):(?<lineNumber>\\d+)\\))?$");

    @Nullable
    private static StackTraceElement[] deserializeStackTrace(@Nullable final String stackTrace) {
        if (stackTrace == null || stackTrace.isEmpty()) {
            return null;
        }

        return stackTrace.lines()
                .map(serializedElement -> {
                    final Matcher matcher = STACK_TRACE_ELEMENT_PATTERN.matcher(serializedElement);
                    if (!matcher.find()) {
                        throw new IllegalArgumentException("Malformed stack trace element: " + stackTrace);
                    }

                    return new StackTraceElement(
                            matcher.group("className"),
                            matcher.group("methodName"),
                            matcher.group("fileName"),
                            matcher.group("lineNumber") != null
                                    ? Integer.parseInt(matcher.group("lineNumber"))
                                    : -1);
                })
                .toArray(StackTraceElement[]::new);
    }

}
