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
package org.dependencytrack.workflow.engine.api;

import org.dependencytrack.workflow.api.WorkflowContext;
import org.dependencytrack.workflow.api.WorkflowExecutor;
import org.dependencytrack.workflow.api.annotation.Workflow;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class WorkflowGroupTest {

    @Test
    void shouldThrowWhenNameIsNull() {
        assertThatExceptionOfType(NullPointerException.class)
                .isThrownBy(() -> new WorkflowGroup(null))
                .withMessage("name must not be null");
    }

    @Test
    void shouldThrowWhenWorkflowNamesIsNull() {
        assertThatExceptionOfType(NullPointerException.class)
                .isThrownBy(() -> new WorkflowGroup("name", null, 1))
                .withMessage("workflowNames must not be null");
    }

    @Test
    void withWorkflowShouldAddWorkflowByName() {
        final var group = new WorkflowGroup("name")
                .withWorkflow("foo");

        assertThat(group.workflowNames()).containsOnly("foo");
    }

    @Workflow(name = "foo")
    static class TestWorkflow implements WorkflowExecutor<Void, Void> {

        @Override
        public Optional<Void> execute(final WorkflowContext<Void> ctx) {
            return Optional.empty();
        }

    }

    @Test
    void withWorkflowShouldAddWorkflowByExecutorClass() {
        final var group = new WorkflowGroup("name")
                .withWorkflow(TestWorkflow.class);

        assertThat(group.workflowNames()).containsOnly("foo");
    }

    static class TestWorkflowWithoutAnnotation implements WorkflowExecutor<Void, Void> {

        @Override
        public Optional<Void> execute(final WorkflowContext<Void> ctx) {
            return Optional.empty();
        }

    }

    @Test
    void withWorkflowShouldThrowWhenWorkflowExecutorClassIsMissingAnnotation() {
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> new WorkflowGroup("name").withWorkflow(TestWorkflowWithoutAnnotation.class))
                .withMessage("""
                        No @org.dependencytrack.workflow.api.annotation.Workflow annotation found for executor \
                        org.dependencytrack.workflow.engine.api.WorkflowGroupTest$TestWorkflowWithoutAnnotation""");
    }

    @Test
    void withMaxConcurrencyShouldSetMaxConcurrency() {
        final var group = new WorkflowGroup("name")
                .withMaxConcurrency(666);

        assertThat(group.maxConcurrency()).isEqualTo(666);
    }

    @Test
    void withMaxConcurrencyShouldThrowWhenMaxConcurrencyIsZeroOrNegative() {
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> new WorkflowGroup("name").withMaxConcurrency(-1))
                .withMessage("maxConcurrency must be greater than 0");

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> new WorkflowGroup("name").withMaxConcurrency(0))
                .withMessage("maxConcurrency must be greater than 0");
    }

}