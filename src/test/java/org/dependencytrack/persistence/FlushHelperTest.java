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
package org.dependencytrack.persistence;

import org.junit.Before;
import org.junit.Test;

import javax.jdo.PersistenceManager;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

public class FlushHelperTest {

    private PersistenceManager pmMock;

    @Before
    public void setUp() {
        pmMock = mock(PersistenceManager.class);
    }

    @Test
    public void testMaybeFlush() {
        final var flushHelper = new FlushHelper(pmMock, 3);

        assertThat(flushHelper.maybeFlush()).isFalse();
        verify(pmMock, never()).flush();

        assertThat(flushHelper.maybeFlush()).isFalse();
        verify(pmMock, never()).flush();

        assertThat(flushHelper.maybeFlush()).isTrue();
        verify(pmMock, times(1)).flush();
    }

    @Test
    public void testFlushIfPending() {
        final var flushHelper = new FlushHelper(pmMock, 3);

        assertThat(flushHelper.flushIfPending()).isFalse();
        verify(pmMock, never()).flush();

        assertThat(flushHelper.maybeFlush()).isFalse();
        verify(pmMock, never()).flush();

        assertThat(flushHelper.flushIfPending()).isTrue();
        verify(pmMock, times(1)).flush();
    }

    @Test
    public void testAutoClose() {
        try (final var flushHelper = new FlushHelper(pmMock, 3)) {
            assertThat(flushHelper.maybeFlush()).isFalse();
            verify(pmMock, never()).flush();
        }

        verify(pmMock, times(1)).flush();
    }

}