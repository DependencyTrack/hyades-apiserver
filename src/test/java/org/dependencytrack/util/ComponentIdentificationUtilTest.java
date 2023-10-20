package org.dependencytrack.util;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentMetaInformation;
import org.dependencytrack.model.FetchStatus;
import org.dependencytrack.model.IntegrityAnalysis;
import org.dependencytrack.model.IntegrityMatchStatus;
import org.dependencytrack.model.IntegrityMetaComponent;
import org.dependencytrack.model.Project;
import org.junit.Assert;
import org.junit.Test;

import java.util.Date;

import static org.dependencytrack.model.IntegrityMatchStatus.HASH_MATCH_PASSED;
import static org.dependencytrack.model.IntegrityMatchStatus.HASH_MATCH_UNKNOWN;

public class ComponentIdentificationUtilTest extends PersistenceCapableTest {

    @Test
    public void testGetMetaInformation() {
        Project project = qm.createProject("Acme Application", null, null, null, null, null, true, false);
        Component component = new Component();
        component.setProject(project);
        component.setName("ABC");
        component.setPurl("pkg:maven/org.acme/abc");
        IntegrityAnalysis integrityAnalysis = new IntegrityAnalysis();
        integrityAnalysis.setComponent(component);
        integrityAnalysis.setIntegrityCheckStatus(IntegrityMatchStatus.HASH_MATCH_PASSED);
        Date published = new Date();
        integrityAnalysis.setUpdatedAt(published);
        integrityAnalysis.setId(component.getId());
        integrityAnalysis.setMd5HashMatchStatus(IntegrityMatchStatus.HASH_MATCH_PASSED);
        integrityAnalysis.setSha1HashMatchStatus(HASH_MATCH_UNKNOWN);
        integrityAnalysis.setSha256HashMatchStatus(HASH_MATCH_UNKNOWN);
        integrityAnalysis.setSha512HashMatchStatus(HASH_MATCH_PASSED);
        qm.persist(integrityAnalysis);
        IntegrityMetaComponent integrityMetaComponent = new IntegrityMetaComponent();
        integrityMetaComponent.setPurl(component.getPurl().toString());
        integrityMetaComponent.setPublishedAt(published);
        integrityMetaComponent.setLastFetch(published);
        integrityMetaComponent.setStatus(FetchStatus.PROCESSED);
        qm.createIntegrityMetaComponent(integrityMetaComponent);
        component = qm.createComponent(component, false);
        ComponentMetaInformation componentMetaInformation = ComponentMetaInformationUtil.getMetaInformation(component.getPurl(), component.getUuid());
        Assert.assertEquals(HASH_MATCH_PASSED, componentMetaInformation.integrityMatchStatus());
        Assert.assertEquals(integrityMetaComponent.getPublishedAt(), componentMetaInformation.publishedDate());
        Assert.assertEquals(integrityMetaComponent.getLastFetch(), componentMetaInformation.lastFetched());
    }
}
