package org.dependencytrack.persistence;

import org.dependencytrack.AbstractPostgresEnabledTest;
import org.dependencytrack.model.FetchStatus;
import org.dependencytrack.model.IntegrityMetaComponent;
import org.junit.Test;

import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;

public class IntegrityMetaQueryManagerPostgresTest extends AbstractPostgresEnabledTest {

    @Test
    public void testCreateIntegrityMetadataHandlingConflict() {
        var integrityMeta = new IntegrityMetaComponent();
        integrityMeta.setPurl("pkg:maven/acme/example@1.0.0?type=jar");
        integrityMeta.setStatus(FetchStatus.IN_PROGRESS);
        integrityMeta.setLastFetch(new Date());
        qm.createIntegrityMetaHandlingConflict(integrityMeta);

        var integrityMeta2 = new IntegrityMetaComponent();
        //inserting same purl twice should not cause exception
        integrityMeta2.setPurl("pkg:maven/acme/example@1.0.0?type=jar");
        integrityMeta2.setStatus(FetchStatus.IN_PROGRESS);
        integrityMeta2.setLastFetch(new Date());
        assertThat(qm.getIntegrityMetaComponentCount()).isEqualTo(1);
    }
}
