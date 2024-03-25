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