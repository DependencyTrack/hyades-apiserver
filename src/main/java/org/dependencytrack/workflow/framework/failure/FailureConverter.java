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
package org.dependencytrack.workflow.framework.failure;

import com.google.protobuf.DebugFormat;
import org.dependencytrack.workflow.framework.proto.v1alpha1.ActivityFailureDetails;
import org.dependencytrack.workflow.framework.proto.v1alpha1.ApplicationFailureDetails;
import org.dependencytrack.workflow.framework.proto.v1alpha1.CancellationFailureDetails;
import org.dependencytrack.workflow.framework.proto.v1alpha1.SideEffectFailureDetails;
import org.dependencytrack.workflow.framework.proto.v1alpha1.SubWorkflowFailureDetails;
import org.dependencytrack.workflow.framework.proto.v1alpha1.WorkflowFailure;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

public final class FailureConverter {

    private FailureConverter() {
    }

    public static WorkflowFailureException toException(final WorkflowFailure failure) {
        final WorkflowFailureException cause = failure.hasCause()
                ? toException(failure.getCause())
                : null;

        final WorkflowFailureException exception = switch (failure.getFailureDetailsCase()) {
            case ACTIVITY_FAILURE_DETAILS -> {
                final ActivityFailureDetails details = failure.getActivityFailureDetails();
                yield new ActivityFailureException(details.getActivityName(), details.getActivityVersion(), cause);
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

        if (failure.getStackTraceCount() > 0) {
            exception.setStackTrace(convertStackTrace(failure.getStackTraceList()));
        }

        return exception;
    }

    public static WorkflowFailure toFailure(final Throwable throwable) {
        final WorkflowFailure.Builder failureBuilder = WorkflowFailure.newBuilder();

        switch (throwable) {
            case final ActivityFailureException activityException -> failureBuilder
                    .setMessage(activityException.getOriginalMessage())
                    .setActivityFailureDetails(
                            ActivityFailureDetails.newBuilder()
                                    .setActivityName(activityException.getActivityName())
                                    .setActivityVersion(activityException.getActivityVersion())
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
            failureBuilder.addAllStackTrace(convertStackTrace(throwable.getStackTrace()));
        }

        if (throwable.getCause() != null) {
            failureBuilder.setCause(toFailure(throwable.getCause()));
        }

        return failureBuilder.build();
    }

    private static List<WorkflowFailure.StackTraceElement> convertStackTrace(final StackTraceElement[] stackTrace) {
        if (stackTrace == null || stackTrace.length == 0) {
            return Collections.emptyList();
        }

        final var convertedStackTrace = new ArrayList<WorkflowFailure.StackTraceElement>(stackTrace.length);
        for (final StackTraceElement element : stackTrace) {
            // Cut the stack trace off before it enters engine internals.
            // These are not necessary for communicating failures in user code.
            if (element.getClassName().equals("org.dependencytrack.workflow.framework.ActivityTaskProcessor")
                || element.getClassName().equals("org.dependencytrack.workflow.framework.WorkflowTaskProcessor")) {
                break;
            }

            final var elementBuilder = WorkflowFailure.StackTraceElement.newBuilder()
                    .setClassName(element.getClassName())
                    .setMethodName(element.getMethodName());
            if (element.getFileName() != null) {
                elementBuilder.setFileName(element.getFileName());
            }
            if (element.getLineNumber() > 0) {
                elementBuilder.setLineNumber(element.getLineNumber());
            }

            convertedStackTrace.add(elementBuilder.build());
        }

        return convertedStackTrace;
    }

    private static StackTraceElement[] convertStackTrace(final List<WorkflowFailure.StackTraceElement> stackTrace) {
        if (stackTrace == null || stackTrace.isEmpty()) {
            return null;
        }

        return stackTrace.stream()
                .map(element -> new StackTraceElement(
                        element.getClassName(),
                        element.getMethodName(),
                        element.hasFileName() ? element.getFileName() : null,
                        element.hasLineNumber() ? element.getLineNumber() : -1))
                .toArray(StackTraceElement[]::new);
    }

}
