package org.dependencytrack.persistence;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentMetaInformation;
import org.dependencytrack.model.FetchStatus;
import org.dependencytrack.model.IntegrityAnalysis;
import org.dependencytrack.model.IntegrityMatchStatus;
import org.dependencytrack.model.IntegrityMetaComponent;
import org.dependencytrack.model.Project;
import org.junit.Test;

import java.util.Date;

import static org.dependencytrack.model.IntegrityMatchStatus.HASH_MATCH_PASSED;
import static org.dependencytrack.model.IntegrityMatchStatus.HASH_MATCH_UNKNOWN;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

public class QueryManagerTest extends PersistenceCapableTest {
    @Test
    public void testGetMetaInformation() {
        Project project = qm.createProject("Acme Application", null, null, null, null, null, true, false);
        Component component = new Component();
        component.setProject(project);
        component.setName("ABC");
        component.setPurl("pkg:maven/org.acme/abc");
        //add another component for better testing
        Component component2 = new Component();
        component2.setProject(project);
        component2.setName("ABC");
        component2.setPurl("pkg:maven/org.acme/abc");

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
        integrityMetaComponent.setRepositoryUrl("repo.url.com");
        qm.createIntegrityMetaComponent(integrityMetaComponent);
        component = qm.createComponent(component, false);
        ComponentMetaInformation componentMetaInformation = qm.getMetaInformation(component.getUuid());
        assertEquals(HASH_MATCH_PASSED, componentMetaInformation.integrityMatchStatus());
        assertEquals(integrityMetaComponent.getPublishedAt(), componentMetaInformation.publishedDate());
        assertEquals(integrityMetaComponent.getLastFetch(), componentMetaInformation.lastFetched());
        assertEquals(integrityMetaComponent.getRepositoryUrl(), componentMetaInformation.integrityRepoUrl());
    }

    @Test
    public void testGetMetaInformationWhenPublishedAtIsMissing() {
        Project project = qm.createProject("Acme Application", null, null, null, null, null, true, false);
        Component component = new Component();
        component.setProject(project);
        component.setName("ABC");
        component.setPurl("pkg:maven/org.acme/abc");
        IntegrityAnalysis integrityAnalysis = new IntegrityAnalysis();
        integrityAnalysis.setComponent(component);
        integrityAnalysis.setIntegrityCheckStatus(IntegrityMatchStatus.HASH_MATCH_PASSED);
        integrityAnalysis.setUpdatedAt(new Date());
        integrityAnalysis.setId(component.getId());
        integrityAnalysis.setMd5HashMatchStatus(IntegrityMatchStatus.HASH_MATCH_PASSED);
        integrityAnalysis.setSha1HashMatchStatus(HASH_MATCH_UNKNOWN);
        integrityAnalysis.setSha256HashMatchStatus(HASH_MATCH_UNKNOWN);
        integrityAnalysis.setSha512HashMatchStatus(HASH_MATCH_PASSED);
        qm.persist(integrityAnalysis);
        IntegrityMetaComponent integrityMetaComponent = new IntegrityMetaComponent();
        integrityMetaComponent.setPurl(component.getPurl().toString());
        integrityMetaComponent.setStatus(FetchStatus.PROCESSED);
        qm.createIntegrityMetaComponent(integrityMetaComponent);
        component = qm.createComponent(component, false);
        ComponentMetaInformation componentMetaInformation = qm.getMetaInformation(component.getUuid());
        assertEquals(HASH_MATCH_PASSED, componentMetaInformation.integrityMatchStatus());
        assertNull(componentMetaInformation.publishedDate());
        assertNull(componentMetaInformation.lastFetched());
    }

    @Test
    public void testGetMetaInformationWhenIntregrityAnalysisIsMissing() {
        Project project = qm.createProject("Acme Application", null, null, null, null, null, true, false);
        Component component = new Component();
        component.setProject(project);
        component.setName("ABC");
        component.setPurl("pkg:maven/org.acme/abc");
        IntegrityMetaComponent integrityMetaComponent = new IntegrityMetaComponent();
        integrityMetaComponent.setPurl(component.getPurl().toString());
        integrityMetaComponent.setStatus(FetchStatus.PROCESSED);
        qm.createIntegrityMetaComponent(integrityMetaComponent);
        component = qm.createComponent(component, false);
        ComponentMetaInformation componentMetaInformation = qm.getMetaInformation(component.getUuid());
        assertNull(componentMetaInformation.publishedDate());
        assertNull(componentMetaInformation.lastFetched());
    }
}
