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
package org.dependencytrack.parser.cyclonedx.util;

import java.util.List;
import java.util.UUID;

import org.cyclonedx.model.Dependency;
import org.cyclonedx.model.Metadata;
import org.cyclonedx.model.Property;
import org.cyclonedx.model.component.crypto.enums.AssetType;
import org.cyclonedx.model.component.crypto.enums.CryptoFunction;
import org.cyclonedx.model.component.crypto.enums.Padding;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import com.github.packageurl.PackageURLBuilder;

public class ModelConverterTest extends PersistenceCapableTest {

    Project project;

    @Before
    public void before() throws Exception {
        super.before();
        this.project = new Project();
        project.setName("testProject");
        project.setUuid(UUID.randomUUID());
        qm.persist(project);
    }

    @Test
    public void testConvertCycloneDX1() throws MalformedPackageURLException {
        org.cyclonedx.model.Component component = new org.cyclonedx.model.Component();
        component.setName("testComponent");
        component.setType(org.cyclonedx.model.Component.Type.CRYPTOGRAPHIC_ASSET);

        PackageURL purl = PackageURLBuilder.aPackageURL()
                .withType("maven").withNamespace("acme").withName("product").withVersion("1.0").build();
        component.setPurl(purl);

        Property property = new Property();
        property.setName("testName");
        property.setValue("testValue");
        component.setProperties(List.of(property));

        org.cyclonedx.model.Component component2 = new org.cyclonedx.model.Component();
        component2.setName("testComponent");
        component2.setType(org.cyclonedx.model.Component.Type.LIBRARY);
        component.setComponents(List.of(component2));

        org.cyclonedx.model.component.crypto.CryptoProperties cryptoProperties = new org.cyclonedx.model.component.crypto.CryptoProperties();
        cryptoProperties.setOid("oid:2.16.840.1.101.3.4.1.6");
        cryptoProperties.setAssetType(AssetType.ALGORITHM);

        org.cyclonedx.model.component.crypto.AlgorithmProperties algorithmProperties = new org.cyclonedx.model.component.crypto.AlgorithmProperties();
        algorithmProperties.setPadding(Padding.PKCS7);
        algorithmProperties.setCryptoFunctions(List.of(CryptoFunction.DECRYPT));
        cryptoProperties.setAlgorithmProperties(algorithmProperties);

        component.setCryptoProperties(cryptoProperties);

        Component newComponent = ModelConverter.convertComponent(component);

        Assert.assertEquals("testComponent", newComponent.getName());
        Assert.assertEquals(Classifier.CRYPTOGRAPHIC_ASSET, newComponent.getClassifier());

        Assert.assertEquals(purl, newComponent.getPurl());
        Assert.assertEquals(purl, newComponent.getPurlCoordinates());

        Assert.assertEquals("testName", newComponent.getProperties().get(0).getPropertyName());
        Assert.assertEquals("testValue", newComponent.getProperties().get(0).getPropertyValue());

        Assert.assertEquals(1, newComponent.getChildren().size());

        Assert.assertEquals("oid:2.16.840.1.101.3.4.1.6", newComponent.getCryptoAssetProperties().getOid());
        Assert.assertEquals(AssetType.ALGORITHM, newComponent.getCryptoAssetProperties().getAssetType());
        Assert.assertEquals(Padding.PKCS7, newComponent.getCryptoAssetProperties().getAlgorithmProperties().getPadding());
        Assert.assertEquals(List.of(CryptoFunction.DECRYPT), newComponent.getCryptoAssetProperties().getAlgorithmProperties().getCryptoFunctions());
    }

    @Test
    public void testConvertCycloneDX2() {
        org.cyclonedx.model.Component component = new org.cyclonedx.model.Component();
        component.setName("testComponent");
        component.setType(org.cyclonedx.model.Component.Type.LIBRARY);

        Component newComponent = ModelConverter.convertComponent(component);

        Assert.assertNull(newComponent.getCryptoAssetProperties());
    }

    // @Test
    // public void testConvertCycloneDXWithToolHash() throws MalformedPackageURLException {
    //     //Project project = qm.createProject("Acme Application", null, null, null, null, null, true, false);

    //     org.cyclonedx.model.Bom bom = new org.cyclonedx.model.Bom();
    //     bom.setSerialNumber("urn:uuid:44371afa-c7cf-48cf-b385-17795344811a");
    //     bom.setVersion(1);

    //     Metadata metadata = new Metadata();

    //     org.cyclonedx.model.Component metaDataComponent = new org.cyclonedx.model.Component();
    //     metaDataComponent.setBomRef("alg:fips197/generic");
    //     metaDataComponent.setType(org.cyclonedx.model.Component.Type.CRYPTOGRAPHIC_ASSET);
    //     metaDataComponent.setName("test");
    //     metaDataComponent.setVersion("test");
    //     metadata.setComponent(metaDataComponent);

    //     Tool scanner = new Tool();
    //     scanner.setName("testScanner");
    //     scanner.setVendor("testVendor");
    //     metadata.setTools(List.of(scanner));

    //     bom.setMetadata(metadata);

    //     org.cyclonedx.model.Component c1 = new org.cyclonedx.model.Component();
    //     c1.setBomRef("alg:fips197/c1");
    //     c1.setName("c1");
    //     c1.setVersion("c1");
    //     c1.setType(org.cyclonedx.model.Component.Type.LIBRARY);
    //     org.cyclonedx.model.Component c2 = new org.cyclonedx.model.Component();
    //     c2.setBomRef("alg:fips197/c2");
    //     c2.setName("c2");
    //     c2.setVersion("c2");
    //     c2.setType(org.cyclonedx.model.Component.Type.CRYPTOGRAPHIC_ASSET);
    //     bom.setComponents(List.of(c1,c2));

    //     Dependency d1 = new Dependency("alg:fips197/c1");
    //     d1.addDependency(new Dependency("alg:fips197/c2"));
    //     // d1.setType(Dependency.Type.USES);
    //     bom.setDependencies(List.of(d1));

    //     List<Component> components = ModelConverter.convertComponents(bom.getComponents());
    //     Set<String> toolHashes = components.stream().map(Component::getToolingHash).collect(Collectors.toSet());
    //     // both hashes are equal
    //     Assert.assertEquals(1, toolHashes.size());
    // }


    @Test
    public void testGenerateDependencies() {
        Project acmeProject = qm.createProject("Acme Application", null, null, null, null, null, true, false);

        org.cyclonedx.model.Bom bom = new org.cyclonedx.model.Bom();
        bom.setSerialNumber("urn:uuid:44371afa-c7cf-48cf-b385-17795344811a");
        bom.setVersion(1);

        Metadata metadata = new Metadata();
        org.cyclonedx.model.Component metaDataComponent = new org.cyclonedx.model.Component();
        metaDataComponent.setBomRef("alg:fips197/generic");
        metaDataComponent.setType(org.cyclonedx.model.Component.Type.CRYPTOGRAPHIC_ASSET);
        metaDataComponent.setName("test");
        metaDataComponent.setVersion("test");
        metadata.setComponent(metaDataComponent);
        bom.setMetadata(metadata);

        org.cyclonedx.model.Component c1 = new org.cyclonedx.model.Component();
        c1.setBomRef("alg:fips197/c1");
        c1.setName("c1");
        c1.setVersion("c1");
        c1.setType(org.cyclonedx.model.Component.Type.LIBRARY);
        org.cyclonedx.model.Component c2 = new org.cyclonedx.model.Component();
        c2.setBomRef("alg:fips197/c2");
        c2.setName("c2");
        c2.setVersion("c2");
        c2.setType(org.cyclonedx.model.Component.Type.CRYPTOGRAPHIC_ASSET);
        bom.setComponents(List.of(c1,c2));

        Dependency d1 = new Dependency("alg:fips197/c1");
        d1.addDependency(new Dependency("alg:fips197/c2"));
        //d1.setType(Dependency.Type.USES);
        bom.setDependencies(List.of(d1));

        List<Component> components = ModelConverter.convertComponents(bom.getComponents());
        components.forEach(c -> c.setProject(acmeProject));
        this.qm.persist(components);
        
        components.get(0).setDirectDependencies("""
                [
                    {"uuid": "%s"}
                ]
                """.formatted(components.get(1).getUuid()));
        List<Dependency> dependencies = DependencyUtil.generateDependencies(acmeProject, components);
        Assert.assertEquals(dependencies.size(), bom.getDependencies().size());
    }

}
