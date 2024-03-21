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
