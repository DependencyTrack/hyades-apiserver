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

import org.cyclonedx.model.component.crypto.enums.AssetType;
import org.cyclonedx.model.component.crypto.enums.Primitive;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentIdentity;
import org.dependencytrack.model.CryptoAlgorithmProperties;
import org.dependencytrack.model.CryptoAssetProperties;
import org.dependencytrack.model.Project;

import org.junit.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

public class CryptoAssetQueryManagerTest extends PersistenceCapableTest {

    private Component persistCryptoAsset() {
        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-crypto");
        component.setVersion("1.0.0");
        component.setClassifier(Classifier.CRYPTOGRAPHIC_ASSET);
        component.setBomRef("x");

        CryptoAlgorithmProperties cap = new CryptoAlgorithmProperties();
        cap.setPrimitive(Primitive.AE);
        cap.setParameterSetIdentifier("128");

        CryptoAssetProperties cp = new CryptoAssetProperties();
        cp.setAssetType(AssetType.ALGORITHM);
        cp.setAlgorithmProperties(cap);

        component.setCryptoAssetProperties(cp);
        return qm.persist(component);
    }

    @Test
    public void testGetAllCryptoAssets() {
        Component component = persistCryptoAsset();
        List<Component> components = qm.getAllCryptoAssets();
        assertThat(components).isNotNull();
        assertThat(components).hasSize(1);
        assertThat(components).satisfiesExactlyInAnyOrder(c -> {
                    assertThat(c.getClassifier()).isEqualTo(component.getClassifier());
                    assertThat(c.getCryptoAssetProperties()).isEqualTo(component.getCryptoAssetProperties());
                });
    }

    @Test
    public void testGetAllCryptoAssetsPerProject() {
        Component component = persistCryptoAsset();
        List<Component> components = qm.getAllCryptoAssets(component.getProject());
        assertThat(components).isNotNull();
        assertThat(components).hasSize(1);
        assertThat(components).satisfiesExactlyInAnyOrder(c -> {
                    assertThat(c.getClassifier()).isEqualTo(component.getClassifier());
                    assertThat(c.getCryptoAssetProperties()).isEqualTo(component.getCryptoAssetProperties());
                });
    }

    @Test
    public void testGetAllCryptoAssetByIdentity() {
        Component component = persistCryptoAsset();
        List<Component> components = qm.getCryptoAssets(new ComponentIdentity(AssetType.ALGORITHM)).getList(Component.class);
        assertThat(components).isNotNull();
        assertThat(components).hasSize(1);
        assertThat(components).satisfiesExactlyInAnyOrder(c -> {
                    assertThat(c.getClassifier()).isEqualTo(component.getClassifier());
                    assertThat(c.getCryptoAssetProperties()).isEqualTo(component.getCryptoAssetProperties());
                });
    }
}