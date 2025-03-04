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

import alpine.model.IConfigProperty;
import org.apache.commons.collections4.MultiValuedMap;
import org.cyclonedx.proto.v1_6.Classification;
import org.cyclonedx.proto.v1_6.Component;
import org.cyclonedx.proto.v1_6.DataFlow;
import org.cyclonedx.proto.v1_6.DataFlowDirection;
import org.cyclonedx.proto.v1_6.Dependency;
import org.cyclonedx.proto.v1_6.ExternalReference;
import org.cyclonedx.proto.v1_6.ExternalReferenceType;
import org.cyclonedx.proto.v1_6.Hash;
import org.cyclonedx.proto.v1_6.HashAlg;
import org.cyclonedx.proto.v1_6.License;
import org.cyclonedx.proto.v1_6.LicenseChoice;
import org.cyclonedx.proto.v1_6.Metadata;
import org.cyclonedx.proto.v1_6.OrganizationalContact;
import org.cyclonedx.proto.v1_6.OrganizationalEntity;
import org.cyclonedx.proto.v1_6.Property;
import org.cyclonedx.proto.v1_6.Service;
import org.cyclonedx.proto.v1_6.Tool;
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.DataClassification;
import org.junit.Before;
import org.junit.Test;

import java.util.List;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

public class ModelConverterProtoTest {

    private ModelConverterProto modelConverter;
    private Component cdxcomponent;
    private OrganizationalContact cdxContact;
    private ExternalReference cdxExternalReference;

    @Before
    public void setUp() throws Exception {
        modelConverter = new ModelConverterProto();
        cdxContact = OrganizationalContact.newBuilder()
                .setName("contact-name")
                .setPhone("123-456-7890")
                .setEmail("test@mail.com").build();
        cdxExternalReference = ExternalReference.newBuilder()
                .setType(ExternalReferenceType.EXTERNAL_REFERENCE_TYPE_BOM)
                .setUrl("https://external.reference.com").build();
        cdxcomponent = Component.newBuilder()
                .setType(Classification.CLASSIFICATION_CONTAINER)
                .setPurl("pkg:npm/test@1.2")
                .setName("component")
                .addAuthors(cdxContact)
                .addHashes(Hash.newBuilder().setAlg(HashAlg.HASH_ALG_MD_5).setValue("component-md5").build())
                .addExternalReferences(cdxExternalReference).build();
    }

    @Test
    public void convertToProjectMetadataTest() {
        final var cdxMetadata = Metadata.newBuilder()
                .setSupplier(OrganizationalEntity.newBuilder()
                        .setName("supplier")
                        .addContact(cdxContact)
                        .addUrl("http://test.url.com").build())
                .addAuthors(cdxContact)
                .setTools(Tool.newBuilder()
                        .addComponents(cdxcomponent)
                        .addServices(Service.newBuilder()
                                .setName("service")
                                .build()).build())
                .build();
        final var projectMetadata = modelConverter.convertToProjectMetadata(cdxMetadata);
        assertThat(projectMetadata).isNotNull();
        assertThat(projectMetadata.getSupplier()).satisfies(supplier -> {
            assertThat(supplier.getName()).isEqualTo("supplier");
            assertThat(supplier.getContacts().get(0)).satisfies(contact -> {
                assertThat(contact.getName()).isEqualTo("contact-name");
                assertThat(contact.getPhone()).isEqualTo("123-456-7890");
                assertThat(contact.getEmail()).isEqualTo("test@mail.com");
            });
        });
        assertThat(projectMetadata.getAuthors().size()).isEqualTo(1);
        assertThat(projectMetadata.getTools()).satisfies(tool -> {
            assertThat(tool.components().get(0)).satisfies(component -> {
                assertThat(component.getName()).isEqualTo("component");
                assertThat(component.getPurl().canonicalize()).isEqualTo("pkg:npm/test@1.2");
                assertThat(component.getClassifier()).isEqualTo(Classifier.CONTAINER);
                assertThat(component.getAuthors().size()).isEqualTo(1);
                assertThat(component.getMd5()).isEqualTo("component-md5");
                assertThat(component.getExternalReferences().size()).isEqualTo(1);
            });
            assertThat(tool.services().get(0)).satisfies(service ->
                    assertThat(service.getName()).isEqualTo("service"));
        });
    }

    @Test
    public void convertToProjectTest() {
        final var cdxMetadata = Metadata.newBuilder().setComponent(cdxcomponent).build();
        final var project = modelConverter.convertToProject(cdxMetadata);
        assertThat(project).isNotNull();
        assertThat(project.getAuthors().size()).isEqualTo(1);
        assertThat(project.getAuthors().get(0).getName()).isEqualTo("contact-name");
        assertThat(project.getName()).isEqualTo("component");
        assertThat(project.getPurl().canonicalize()).isEqualTo("pkg:npm/test@1.2");
        assertThat(project.getClassifier()).isEqualTo(Classifier.CONTAINER);
        assertThat(project.getExternalReferences().size()).isEqualTo(1);
    }

    @Test
    public void convertComponentsTest() {
        final var components = modelConverter.convertComponents(List.of(cdxcomponent));
        assertThat(components).isNotNull();
        assertThat(components.size()).isEqualTo(1);
        var component = components.get(0);
        assertThat(component.getAuthors().size()).isEqualTo(1);
        assertThat(component.getAuthors().get(0).getName()).isEqualTo("contact-name");
        assertThat(component.getName()).isEqualTo("component");
        assertThat(component.getPurl().canonicalize()).isEqualTo("pkg:npm/test@1.2");
        assertThat(component.getClassifier()).isEqualTo(Classifier.CONTAINER);
        assertThat(component.getExternalReferences().size()).isEqualTo(1);
        assertThat(component.getMd5()).isEqualTo("component-md5");
    }

    @Test
    public void convertServicesTest() {
        final var cdxService = Service.newBuilder()
                .setName("service")
                .setVersion("1.2.3")
                .setAuthenticated(false)
                .addData(DataFlow.newBuilder()
                        .setFlow(DataFlowDirection.DATA_FLOW_INBOUND)
                        .setValue("data-inbound-service").build())
                .addExternalReferences(cdxExternalReference).build();
        final var services = modelConverter.convertServices(List.of(cdxService));
        assertThat(services).isNotNull();
        assertThat(services.size()).isEqualTo(1);
        var service = services.get(0);
        assertThat(service).isNotNull();
        assertThat(service.getExternalReferences().size()).isEqualTo(1);
        assertThat(service.getName()).isEqualTo("service");
        assertThat(service.getVersion()).isEqualTo("1.2.3");
        assertThat(service.getAuthenticated()).isEqualTo(false);
        assertThat(service.getData().get(0)).satisfies(serviceData -> {
            assertThat(serviceData.getName()).isEqualTo("data-inbound-service");
            assertThat(serviceData.getDirection()).isEqualTo(DataClassification.Direction.INBOUND);
        });
    }

    @Test
    public void convertDependencyGraphTest() {
        final Dependency cdxDependency = Dependency.newBuilder()
                .addDependencies(Dependency.newBuilder()
                        .setRef("dependency-ref").build()).build();
        MultiValuedMap<String, String> dependencyGraph = modelConverter.convertDependencyGraph(List.of(cdxDependency));
        assertThat(dependencyGraph).isNotNull();
        assertThat(dependencyGraph.size()).isEqualTo(1);
    }

    @Test
    public void convertLicencesTest() {
        final LicenseChoice cdxLicense = LicenseChoice.newBuilder()
                .setLicense(License.newBuilder()
                        .setId("license-id")
                        .setName("license-name")
                        .setUrl("https://license.com").build()).build();
        var licenses = modelConverter.convertLicences(List.of(cdxLicense));
        assertThat(licenses).isNotNull();
        assertThat(licenses.size()).isEqualTo(1);
    }

    @Test
    public void convertToolsTest() {
        final Tool cdxTool = Tool.newBuilder()
                .setVendor("tool-vendor")
                .setName("tool-name")
                .setVersion("1.2")
                .addExternalReferences(cdxExternalReference)
                .addHashes(Hash.newBuilder()
                        .setAlg(HashAlg.HASH_ALG_SHA_1)
                        .setValue("sha-1").build()).build();
        org.dependencytrack.model.Component component = modelConverter.convert(cdxTool);
        assertThat(component).isNotNull();
        assertThat(component.getSupplier().getName()).isEqualTo("tool-vendor");
        assertThat(component.getName()).isEqualTo("tool-name");
        assertThat(component.getVersion()).isEqualTo("1.2");
        assertThat(component.getExternalReferences().size()).isEqualTo(1);
        assertThat(component.getSha1()).isEqualTo("sha-1");
    }

    @Test
    public void convertToComponentPropertiesTest() {
        final var cdxProperty = Property.newBuilder()
                .setValue("property-value")
                .setName("property-name").build();
        var componentProperties = modelConverter.convertToComponentProperties(List.of(cdxProperty));
        assertThat(componentProperties).isNotNull();
        assertThat(componentProperties.size()).isEqualTo(1);
        assertThat(componentProperties.get(0)).satisfies(componentProperty -> {
            assertThat(componentProperty.getPropertyName()).isEqualTo("property-name");
            assertThat(componentProperty.getPropertyValue()).isEqualTo("property-value");
            assertThat(componentProperty.getPropertyType()).isEqualTo(IConfigProperty.PropertyType.STRING);
        });
    }

    @Test
    public void convertOrganizationalEntityTest() {
        final var cdxOrgEntity = OrganizationalEntity.newBuilder()
                .setName("org-entity")
                .addUrl("https://org.entity.com")
                .addContact(cdxContact).build();
        var orgEntity = modelConverter.convertOrganizationalEntity(cdxOrgEntity);
        assertThat(orgEntity).isNotNull();
        assertThat(orgEntity.getName()).isEqualTo("org-entity");
        assertThat(orgEntity.getContacts().size()).isEqualTo(1);
        assertThat(orgEntity.getUrls().length).isEqualTo(1);
    }
}