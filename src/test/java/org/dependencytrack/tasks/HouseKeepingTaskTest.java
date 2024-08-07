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
package org.dependencytrack.tasks;

import alpine.Config;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.common.ConfigKey;
import org.dependencytrack.event.HouseKeepingEvent;
import org.dependencytrack.model.VulnerabilityScan;
import org.dependencytrack.model.WorkflowState;
import org.dependencytrack.model.WorkflowStatus;
import org.dependencytrack.model.WorkflowStep;
import org.jdbi.v3.core.statement.PreparedBatch;
import org.junit.Test;

import javax.jdo.JDOObjectNotFoundException;
import java.sql.Date;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.dependencytrack.common.ConfigKey.WORKFLOW_RETENTION_DURATION;
import static org.dependencytrack.common.ConfigKey.WORKFLOW_STEP_TIMEOUT_DURATION;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.spy;

public class HouseKeepingTaskTest extends PersistenceCapableTest {

    @Test
    public void testBomUploadHouseKeeping() {
        useJdbiTransaction(handle -> {
            final PreparedBatch batch = handle.prepareBatch("""
                    INSERT INTO "BOM_UPLOAD" ("TOKEN", "UPLOADED_AT", "BOM")
                    VALUES (:token, NOW() - :uploadedDurationAgo, :bom)
                    """);

            for (int i = 1; i <= 10; i++) {
                final UUID token = UUID.randomUUID();
                final Duration uploadedDurationAgo = Duration.ofMinutes(i * 10);
                final byte[] bomBytes = "bom-%d".formatted(i).getBytes();

                batch.bind("token", token);
                batch.bind("uploadedDurationAgo", uploadedDurationAgo);
                batch.bind("bom", bomBytes);
                batch.add();
            }

            assertThat(Arrays.stream(batch.execute()).sum()).isEqualTo(10);
        });

        final var configMock = spy(Config.class);
        doReturn("PT1H").when(configMock).getProperty(eq(ConfigKey.BOM_UPLOAD_STORAGE_RETENTION_DURATION));

        final var task = new HouseKeepingTask(configMock);
        assertThatNoException().isThrownBy(() -> task.inform(new HouseKeepingEvent()));

        final int remainingBoms = withJdbiHandle(handle -> handle.createQuery("""
                        SELECT COUNT(*)
                          FROM "BOM_UPLOAD"
                        """)
                .mapTo(Integer.class)
                .one());
        assertThat(remainingBoms).isEqualTo(5);
    }

    @Test
    public void testVulnerabilityScanHouseKeeping() {
        qm.createVulnerabilityScan(VulnerabilityScan.TargetType.PROJECT, UUID.randomUUID(), "token-123", 5);
        final var scanB = qm.createVulnerabilityScan(VulnerabilityScan.TargetType.PROJECT, UUID.randomUUID(), "token-xyz", 1);
        qm.runInTransaction(() -> scanB.setUpdatedAt(Date.from(Instant.now().minus(25, ChronoUnit.HOURS))));
        final var scanC = qm.createVulnerabilityScan(VulnerabilityScan.TargetType.PROJECT, UUID.randomUUID(), "token-1y3", 3);
        qm.runInTransaction(() -> scanC.setUpdatedAt(Date.from(Instant.now().minus(13, ChronoUnit.HOURS))));

        final var configMock = spy(Config.class);

        final var task = new HouseKeepingTask(configMock);
        assertThatNoException().isThrownBy(() -> task.inform(new HouseKeepingEvent()));

        assertThat(qm.getVulnerabilityScan("token-123")).isNotNull();
        assertThat(qm.getVulnerabilityScan("token-xyz")).isNull();
        assertThat(qm.getVulnerabilityScan("token-1y3")).isNotNull();
    }

    @Test
    public void testWorkflowHouseKeepingWithTransitionToTimedOut() {
        final Duration timeoutDuration = Duration.ofHours(6);
        final Duration retentionDuration = Duration.ofHours(666); // Not relevant for this test.
        final Instant now = Instant.now();
        final Instant timeoutCutoff = now.minus(timeoutDuration);

        final var token = UUID.randomUUID();
        final var parentState = new WorkflowState();
        parentState.setStep(WorkflowStep.BOM_CONSUMPTION);
        parentState.setStatus(WorkflowStatus.PENDING);
        parentState.setToken(token);
        parentState.setStartedAt(Date.from(timeoutCutoff.minus(2, ChronoUnit.HOURS)));
        parentState.setUpdatedAt(Date.from(timeoutCutoff.minus(1, ChronoUnit.HOURS)));
        qm.persist(parentState);
        final var childState = new WorkflowState();
        childState.setParent(parentState);
        childState.setStep(WorkflowStep.BOM_PROCESSING);
        childState.setStatus(WorkflowStatus.PENDING);
        childState.setToken(token);
        childState.setUpdatedAt(Date.from(timeoutCutoff.plus(1, ChronoUnit.HOURS)));
        qm.persist(childState);

        final var configMock = spy(Config.class);
        doReturn(retentionDuration.toString()).when(configMock).getProperty(eq(WORKFLOW_RETENTION_DURATION));
        doReturn(timeoutDuration.toString()).when(configMock).getProperty(eq(WORKFLOW_STEP_TIMEOUT_DURATION));

        final var task = new HouseKeepingTask(configMock);
        assertThatNoException().isThrownBy(() -> task.inform(new HouseKeepingEvent()));

        qm.getPersistenceManager().refreshAll(parentState, childState);
        assertThat(parentState.getStatus()).isEqualTo(WorkflowStatus.TIMED_OUT);
        assertThat(parentState.getUpdatedAt()).isAfter(Date.from(timeoutCutoff)); // Modified.
        assertThat(childState.getStatus()).isEqualTo(WorkflowStatus.PENDING);
        assertThat(childState.getUpdatedAt()).isEqualToIgnoringMillis(Date.from(timeoutCutoff.plus(1, ChronoUnit.HOURS))); // Not modified.
    }

    @Test
    public void testWorkflowHouseKeepingWithTransitionTimedOutToFailed() {
        final Duration timeoutDuration = Duration.ofHours(6);
        final Duration retentionDuration = Duration.ofHours(666); // Not relevant for this test.
        final Instant now = Instant.now();
        final Instant timeoutCutoff = now.minus(timeoutDuration);

        final var token = UUID.randomUUID();
        final var parentState = new WorkflowState();
        parentState.setStep(WorkflowStep.BOM_CONSUMPTION);
        parentState.setStatus(WorkflowStatus.TIMED_OUT);
        parentState.setToken(token);
        parentState.setStartedAt(Date.from(timeoutCutoff.minus(2, ChronoUnit.HOURS)));
        parentState.setUpdatedAt(Date.from(timeoutCutoff.minus(1, ChronoUnit.HOURS)));
        qm.persist(parentState);
        final var childState = new WorkflowState();
        childState.setParent(parentState);
        childState.setStep(WorkflowStep.BOM_PROCESSING);
        childState.setStatus(WorkflowStatus.PENDING);
        childState.setToken(token);
        childState.setUpdatedAt(Date.from(timeoutCutoff.plus(1, ChronoUnit.HOURS)));
        qm.persist(childState);

        final var configMock = spy(Config.class);
        doReturn(retentionDuration.toString()).when(configMock).getProperty(eq(WORKFLOW_RETENTION_DURATION));
        doReturn(timeoutDuration.toString()).when(configMock).getProperty(eq(WORKFLOW_STEP_TIMEOUT_DURATION));

        final var task = new HouseKeepingTask(configMock);
        assertThatNoException().isThrownBy(() -> task.inform(new HouseKeepingEvent()));

        qm.getPersistenceManager().refreshAll(parentState, childState);
        assertThat(parentState.getStatus()).isEqualTo(WorkflowStatus.FAILED);
        assertThat(parentState.getFailureReason()).isEqualTo("Timed out");
        assertThat(parentState.getUpdatedAt()).isAfter(timeoutCutoff); // Modified.
        assertThat(childState.getStatus()).isEqualTo(WorkflowStatus.CANCELLED);
        assertThat(childState.getFailureReason()).isNull();
        assertThat(childState.getUpdatedAt()).isEqualTo(parentState.getUpdatedAt()); // Modified.
    }

    @Test
    public void testWorkflowHouseKeepingWithDeleteExpired() {
        final Duration timeoutDuration = Duration.ofHours(666); // Not relevant for this test.
        final Duration retentionDuration = Duration.ofHours(6);
        final Instant now = Instant.now();
        final Instant retentionCutoff = now.minus(retentionDuration);

        // Create a workflow where all steps are in a terminal state,
        // and they all fall below the retention cutoff time.
        final var tokenA = UUID.randomUUID();
        final var parentStateA = new WorkflowState();
        parentStateA.setStep(WorkflowStep.BOM_CONSUMPTION);
        parentStateA.setStatus(WorkflowStatus.FAILED);
        parentStateA.setToken(tokenA);
        parentStateA.setStartedAt(Date.from(retentionCutoff.minus(2, ChronoUnit.HOURS)));
        parentStateA.setUpdatedAt(Date.from(retentionCutoff.minus(1, ChronoUnit.HOURS)));
        qm.persist(parentStateA);
        final var childStateA = new WorkflowState();
        childStateA.setParent(parentStateA);
        childStateA.setStep(WorkflowStep.BOM_PROCESSING);
        childStateA.setStatus(WorkflowStatus.CANCELLED);
        childStateA.setToken(tokenA);
        childStateA.setUpdatedAt(Date.from(retentionCutoff.minus(1, ChronoUnit.HOURS)));
        qm.persist(childStateA);

        // Create a workflow where all steps are in a terminal state,
        // but only one falls below the retention cutoff time.
        final var tokenB = UUID.randomUUID();
        final var parentStateB = new WorkflowState();
        parentStateB.setStep(WorkflowStep.BOM_CONSUMPTION);
        parentStateB.setStatus(WorkflowStatus.COMPLETED);
        parentStateB.setToken(tokenB);
        parentStateB.setStartedAt(Date.from(retentionCutoff.minus(2, ChronoUnit.HOURS)));
        parentStateB.setUpdatedAt(Date.from(retentionCutoff.minus(1, ChronoUnit.HOURS)));
        qm.persist(parentStateB);
        final var childStateB = new WorkflowState();
        childStateB.setParent(parentStateB);
        childStateB.setStep(WorkflowStep.BOM_PROCESSING);
        childStateB.setStatus(WorkflowStatus.FAILED);
        childStateB.setToken(tokenB);
        childStateB.setUpdatedAt(Date.from(retentionCutoff.plus(1, ChronoUnit.HOURS)));
        qm.persist(childStateB);

        // Create a workflow where only one step is in a terminal state,
        // but both fall below the retention cutoff time.
        final var tokenC = UUID.randomUUID();
        final var parentStateC = new WorkflowState();
        parentStateC.setStep(WorkflowStep.BOM_CONSUMPTION);
        parentStateC.setStatus(WorkflowStatus.COMPLETED);
        parentStateC.setToken(tokenC);
        parentStateC.setStartedAt(Date.from(retentionCutoff.minus(4, ChronoUnit.HOURS)));
        parentStateC.setUpdatedAt(Date.from(retentionCutoff.minus(3, ChronoUnit.HOURS)));
        qm.persist(parentStateC);
        final var childStateC = new WorkflowState();
        childStateC.setParent(parentStateC);
        childStateC.setStep(WorkflowStep.BOM_PROCESSING);
        childStateC.setStatus(WorkflowStatus.PENDING);
        childStateC.setToken(tokenC);
        childStateC.setStartedAt(Date.from(retentionCutoff.minus(2, ChronoUnit.HOURS)));
        childStateC.setUpdatedAt(Date.from(retentionCutoff.minus(1, ChronoUnit.HOURS)));
        qm.persist(childStateC);

        final var configMock = spy(Config.class);
        doReturn(retentionDuration.toString()).when(configMock).getProperty(eq(WORKFLOW_RETENTION_DURATION));
        doReturn(timeoutDuration.toString()).when(configMock).getProperty(eq(WORKFLOW_STEP_TIMEOUT_DURATION));

        final var task = new HouseKeepingTask(configMock);
        assertThatNoException().isThrownBy(() -> task.inform(new HouseKeepingEvent()));

        // Workflow A must've been deleted, because all steps are in terminal status, and fall below the retention cutoff.
        assertThatExceptionOfType(JDOObjectNotFoundException.class).isThrownBy(() -> qm.getObjectById(WorkflowState.class, childStateA.getId()));
        assertThatExceptionOfType(JDOObjectNotFoundException.class).isThrownBy(() -> qm.getObjectById(WorkflowState.class, parentStateA.getId()));

        // Workflow B must not have been deleted, because not all steps fall below the retention cutoff.
        assertThatNoException().isThrownBy(() -> qm.getObjectById(WorkflowState.class, childStateB.getId()));
        assertThatNoException().isThrownBy(() -> qm.getObjectById(WorkflowState.class, parentStateB.getId()));

        // Workflow C must not have been deleted, because it still contains steps with non-terminal status.
        assertThatNoException().isThrownBy(() -> qm.getObjectById(WorkflowState.class, childStateC.getId()));
        assertThatNoException().isThrownBy(() -> qm.getObjectById(WorkflowState.class, parentStateC.getId()));
    }

}