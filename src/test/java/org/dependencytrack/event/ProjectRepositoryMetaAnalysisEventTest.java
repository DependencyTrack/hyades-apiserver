package org.dependencytrack.event;

import org.junit.Test;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

public class ProjectRepositoryMetaAnalysisEventTest {

    @Test
    public void testConstructor() {
        final var uuid = UUID.randomUUID();
        final var event = new ProjectRepositoryMetaAnalysisEvent(uuid);
        assertThat(event.projectUuid()).isEqualTo(uuid);
    }

    @Test
    public void testConstructorWithNullArgument() {
        assertThatExceptionOfType(NullPointerException.class)
                .isThrownBy(() -> new ProjectRepositoryMetaAnalysisEvent(null));
    }

}