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

import alpine.common.logging.Logger;
import alpine.model.IConfigProperty;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import org.apache.commons.collections4.MultiValuedMap;
import org.apache.commons.collections4.multimap.HashSetValuedHashMap;
import org.apache.commons.lang3.StringUtils;
import org.cyclonedx.model.ExternalReference.Type;
import org.cyclonedx.model.License;
import org.cyclonedx.proto.v1_6.Classification;
import org.cyclonedx.proto.v1_6.DataFlow;
import org.cyclonedx.proto.v1_6.DataFlowDirection;
import org.cyclonedx.proto.v1_6.Dependency;
import org.cyclonedx.proto.v1_6.ExternalReferenceType;
import org.cyclonedx.proto.v1_6.Metadata;
import org.cyclonedx.proto.v1_6.Property;
import org.cyclonedx.proto.v1_6.Service;
import org.cyclonedx.proto.v1_6.Tool;
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentProperty;
import org.dependencytrack.model.DataClassification;
import org.dependencytrack.model.ExternalReference;
import org.dependencytrack.model.OrganizationalContact;
import org.dependencytrack.model.OrganizationalEntity;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectMetadata;
import org.dependencytrack.model.ServiceComponent;
import org.dependencytrack.model.Tools;
import org.dependencytrack.parser.spdx.expression.SpdxExpressionParser;
import org.dependencytrack.parser.spdx.expression.model.SpdxExpression;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Consumer;

import static java.util.Objects.requireNonNullElse;
import static org.apache.commons.lang3.StringUtils.isNotBlank;
import static org.apache.commons.lang3.StringUtils.trim;
import static org.apache.commons.lang3.StringUtils.trimToNull;
import static org.dependencytrack.util.PurlUtil.silentPurlCoordinatesOnly;

public class ModelConverterProto {

    private static final Logger LOGGER = Logger.getLogger(ModelConverterProto.class);

    /**
     * Private Constructor.
     */
    ModelConverterProto() {
    }

    public static ProjectMetadata convertToProjectMetadata(final Metadata cdxMetadata) {
        final var projectMetadata = new ProjectMetadata();
        if (cdxMetadata.hasSupplier()) {
            projectMetadata.setSupplier(ModelConverterProto.convert(cdxMetadata.getSupplier()));
        }
        if (!cdxMetadata.getAuthorsList().isEmpty()) {
            projectMetadata.setAuthors(ModelConverterProto.convertCdxContacts(cdxMetadata.getAuthorsList()));
        }

        final var toolComponents = new ArrayList<Component>();
        final var toolServices = new ArrayList<ServiceComponent>();
        if (cdxMetadata.hasTools()) {
            if (cdxMetadata.getTools().hasName() && cdxMetadata.getTools().hasVersion()) {
                toolComponents.add(convert(cdxMetadata.getTools()));
            }
            if(cdxMetadata.getTools().getComponentsCount() > 0) {
                cdxMetadata.getTools().getComponentsList().stream().map(ModelConverterProto::convertComponent).forEach(toolComponents::add);
                cdxMetadata.getTools().getServicesList().stream().map(ModelConverterProto::convertService).forEach(toolServices::add);
            }
        }

        if (!toolComponents.isEmpty() || !toolServices.isEmpty()) {
            projectMetadata.setTools(new Tools(
                    toolComponents.isEmpty() ? null : toolComponents,
                    toolServices.isEmpty() ? null : toolServices
            ));
        }

        return projectMetadata;
    }

    public static Project convertToProject(final Metadata cdxMetadata) {
        if (cdxMetadata.hasComponent()) {
            final Project project = convertToProject(cdxMetadata.getComponent());
            project.setManufacturer(convert(cdxMetadata.getManufacture()));
            return project;
        }
        return null;
    }

    public static Project convertToProject(final org.cyclonedx.proto.v1_6.Component cdxComponent) {
        final var project = new Project();
        project.setBomRef(useOrGenerateRandomBomRef(cdxComponent.getBomRef()));
        project.setPublisher(trimToNull(cdxComponent.getPublisher()));
        project.setSupplier(convert(cdxComponent.getSupplier()));
        project.setClassifier(convertClassifier(cdxComponent.getType()).orElse(Classifier.APPLICATION));
        project.setGroup(trimToNull(cdxComponent.getGroup()));
        project.setName(trimToNull(cdxComponent.getName()));
        project.setVersion(trimToNull(cdxComponent.getVersion()));
        project.setDescription(trimToNull(cdxComponent.getDescription()));
        project.setCpe(trimToNull(cdxComponent.getCpe()));
        project.setExternalReferences(convertExternalReferences(cdxComponent.getExternalReferencesList()));

        List<OrganizationalContact> contacts = new ArrayList<>();
        if (cdxComponent.hasAuthor()) {
            contacts.add(new OrganizationalContact() {{
                setName(cdxComponent.getAuthor());
            }});
        }
        if(cdxComponent.getAuthorsCount() > 0){
            contacts.addAll(convertCdxContacts(cdxComponent.getAuthorsList()));
        }
        project.setAuthors(contacts);

        if (cdxComponent.hasPurl()) {
            try {
                final var purl = new PackageURL(cdxComponent.getPurl());
                project.setPurl(purl);
            } catch (MalformedPackageURLException e) {
                LOGGER.debug("Encountered invalid PURL", e);
            }
        }

        if (cdxComponent.hasSwid()) {
            project.setSwidTagId(trimToNull(cdxComponent.getSwid().getTagId()));
        }

        return project;
    }

    public static List<Component> convertComponents(final List<org.cyclonedx.proto.v1_6.Component> cdxComponents) {
        if (cdxComponents.isEmpty()) {
            return Collections.emptyList();
        }

        return cdxComponents.stream().map(ModelConverterProto::convertComponent).toList();
    }

    public static Component convertComponent(final org.cyclonedx.proto.v1_6.Component cdxComponent) {
        final var component = new Component();
        component.setBomRef(useOrGenerateRandomBomRef(cdxComponent.getBomRef()));
        component.setPublisher(trimToNull(cdxComponent.getPublisher()));
        component.setSupplier(convert(cdxComponent.getSupplier()));
        component.setBomRef(trimToNull(cdxComponent.getBomRef()));
        component.setClassifier(convertClassifier(cdxComponent.getType()).orElse(Classifier.LIBRARY));
        component.setGroup(trimToNull(cdxComponent.getGroup()));
        component.setName(requireNonNullElse(trimToNull(cdxComponent.getName()), "-"));
        component.setVersion(trimToNull(cdxComponent.getVersion()));
        component.setDescription(trimToNull(cdxComponent.getDescription()));
        component.setCopyright(trimToNull(cdxComponent.getCopyright()));
        component.setCpe(trimToNull(cdxComponent.getCpe()));
        component.setExternalReferences(convertExternalReferences(cdxComponent.getExternalReferencesList()));
        component.setProperties(convertToComponentProperties(cdxComponent.getPropertiesList()));

        List<OrganizationalContact> contacts = new ArrayList<>();
        if (cdxComponent.hasAuthor()) {
            contacts.add(new OrganizationalContact() {{
                setName(cdxComponent.getAuthor());
            }});
        }
        if (cdxComponent.getAuthorsCount() > 0) {
            contacts.addAll(convertCdxContacts(cdxComponent.getAuthorsList()));
        }
        component.setAuthors(contacts);

        if (cdxComponent.hasPurl()) {
            try {
                final var purl = new PackageURL(cdxComponent.getPurl());
                component.setPurl(purl);
                component.setPurlCoordinates(silentPurlCoordinatesOnly(purl));
            } catch (MalformedPackageURLException e) {
                LOGGER.debug("Encountered invalid PURL", e);
            }
        }

        if (cdxComponent.hasSwid()) {
            component.setSwidTagId(trimToNull(cdxComponent.getSwid().getTagId()));
        }

        if (cdxComponent.getHashesCount() > 0) {
            for (final org.cyclonedx.proto.v1_6.Hash cdxHash : cdxComponent.getHashesList()) {
                final Consumer<String> hashSetter = switch (cdxHash.getAlg()) {
                    case HASH_ALG_MD_5 -> component::setMd5;
                    case HASH_ALG_SHA_1 -> component::setSha1;
                    case HASH_ALG_SHA_256 -> component::setSha256;
                    case HASH_ALG_SHA_384 -> component::setSha384;
                    case HASH_ALG_SHA_512 -> component::setSha512;
                    case HASH_ALG_SHA_3_256 -> component::setSha3_256;
                    case HASH_ALG_SHA_3_384 -> component::setSha3_384;
                    case HASH_ALG_SHA_3_512 -> component::setSha3_512;
                    case HASH_ALG_BLAKE_2_B_256 -> component::setBlake2b_256;
                    case HASH_ALG_BLAKE_2_B_384 -> component::setBlake2b_384;
                    case HASH_ALG_BLAKE_2_B_512 -> component::setBlake2b_512;
                    case HASH_ALG_BLAKE_3 -> component::setBlake3;
                    default -> null;
                };
                if (hashSetter != null) {
                    hashSetter.accept(cdxHash.getValue());
                }
            }
        }

        final var licenseCandidates = new ArrayList<License>();
        if (cdxComponent.getLicensesCount() > 0) {
            licenseCandidates.addAll(convertLicences(cdxComponent.getLicensesList()));

            cdxComponent.getLicensesList().stream().forEach(licenseChoice -> {
                final String licenseExpression = licenseChoice.getExpression();
                if (isNotBlank(licenseExpression)) {
                    // If the expression consists of just one license ID, add it as another option.
                    final var expressionParser = new SpdxExpressionParser();
                    final SpdxExpression expression = expressionParser.parse(licenseExpression);
                    if (!SpdxExpression.INVALID.equals(expression)) {
                        component.setLicenseExpression(trim(licenseExpression));
                        if (expression.getSpdxLicenseId() != null) {
                            final var expressionLicense = new License();
                            expressionLicense.setId(expression.getSpdxLicenseId());
                            expressionLicense.setName(expression.getSpdxLicenseId());
                            licenseCandidates.add(expressionLicense);
                        }
                    } else {
                        LOGGER.warn("""
                            Encountered invalid license expression "%s" for \
                            Component{group=%s, name=%s, version=%s, bomRef=%s}; Skipping\
                            """.formatted(licenseExpression, component.getGroup(),
                                component.getName(), component.getVersion(), component.getBomRef()));
                    }
                }
            });
        }
        component.setLicenseCandidates(licenseCandidates);

        if (cdxComponent.getComponentsCount() > 0) {
            final var children = new ArrayList<Component>();
            for (final org.cyclonedx.proto.v1_6.Component cdxChildComponent : cdxComponent.getComponentsList()) {
                children.add(convertComponent(cdxChildComponent));
            }
            component.setChildren(children);
        }

        return component;
    }

    public static List<License> convertLicences(List<org.cyclonedx.proto.v1_6.LicenseChoice> cdxLicensesList) {
        List<License> licences = new ArrayList<>();
        for (org.cyclonedx.proto.v1_6.LicenseChoice licenseChoice : cdxLicensesList) {
            final var cdxLicense = licenseChoice.getLicense();
            var license = new License();
            if (isNotBlank(cdxLicense.getId()) || isNotBlank(cdxLicense.getName())) {
                license.setId(cdxLicense.getId());
                license.setName(cdxLicense.getName());
                license.setUrl(cdxLicense.getUrl());
                licences.add(license);
            }
        }
        return licences;
    }

    public static Component convert(final Tool tools) {
        final var component = new Component();
        if (tools.hasVendor()) {
            final var supplier = new OrganizationalEntity();
            supplier.setName(trimToNull(tools.getVendor()));
            component.setSupplier(supplier);
        }
        component.setName(trimToNull(tools.getName()));
        component.setVersion(trimToNull(tools.getVersion()));
        component.setExternalReferences(convertExternalReferences(tools.getExternalReferencesList()));

        if (tools.getHashesCount() > 0) {
            for (final org.cyclonedx.proto.v1_6.Hash cdxHash : tools.getHashesList()) {
                final Consumer<String> hashSetter = switch (cdxHash.getAlg()) {
                    case HASH_ALG_MD_5 -> component::setMd5;
                    case HASH_ALG_SHA_1 -> component::setSha1;
                    case HASH_ALG_SHA_256 -> component::setSha256;
                    case HASH_ALG_SHA_384 -> component::setSha384;
                    case HASH_ALG_SHA_512 -> component::setSha512;
                    case HASH_ALG_SHA_3_256 -> component::setSha3_256;
                    case HASH_ALG_SHA_3_384 -> component::setSha3_384;
                    case HASH_ALG_SHA_3_512 -> component::setSha3_512;
                    case HASH_ALG_BLAKE_2_B_256 -> component::setBlake2b_256;
                    case HASH_ALG_BLAKE_2_B_384 -> component::setBlake2b_384;
                    case HASH_ALG_BLAKE_2_B_512 -> component::setBlake2b_512;
                    case HASH_ALG_BLAKE_3 -> component::setBlake3;
                    default -> null;
                };
                if (hashSetter != null) {
                    hashSetter.accept(cdxHash.getValue());
                }
            }
        }

        return component;
    }

    public static OrganizationalEntity convert(final org.cyclonedx.proto.v1_6.OrganizationalEntity cdxEntity) {
        final var dtEntity = new OrganizationalEntity();
        dtEntity.setName(trimToNull(cdxEntity.getName()));
        if (!cdxEntity.getContactList().isEmpty()) {
            dtEntity.setContacts(cdxEntity.getContactList().stream().map(ModelConverterProto::convert).toList());
        }
        if (!cdxEntity.getUrlList().isEmpty()) {
            dtEntity.setUrls(cdxEntity.getUrlList().toArray(new String[0]));
        }
        return dtEntity;
    }

    public static List<OrganizationalContact> convertCdxContacts(final List<org.cyclonedx.proto.v1_6.OrganizationalContact> cdxContacts) {
        return cdxContacts.stream().map(ModelConverterProto::convert).toList();
    }

    private static OrganizationalContact convert(final org.cyclonedx.proto.v1_6.OrganizationalContact cdxContact) {
        final var dtContact = new OrganizationalContact();
        dtContact.setName(trimToNull(cdxContact.getName()));
        dtContact.setEmail(trimToNull(cdxContact.getEmail()));
        dtContact.setPhone(trimToNull(cdxContact.getPhone()));
        return dtContact;
    }

    public static List<ComponentProperty> convertToComponentProperties(final List<Property> cdxProperties) {
        if (cdxProperties.isEmpty()) {
            return Collections.emptyList();
        }

        final var identitiesSeen = new HashSet<ComponentProperty.Identity>();
        return cdxProperties.stream()
                .map(ModelConverterProto::convertToComponentProperty)
                .filter(Objects::nonNull)
                .filter(property -> identitiesSeen.add(new ComponentProperty.Identity(property)))
                .toList();
    }

    private static ComponentProperty convertToComponentProperty(final Property cdxProperty) {
        final var property = new ComponentProperty();
        property.setPropertyValue(trimToNull(cdxProperty.getValue()));
        property.setPropertyType(IConfigProperty.PropertyType.STRING);

        final String cdxPropertyName = trimToNull(cdxProperty.getName());
        if (cdxPropertyName == null) {
            return null;
        }

        // Treat property names according to the CycloneDX namespace syntax:
        // https://cyclonedx.github.io/cyclonedx-property-taxonomy/
        final int firstSeparatorIndex = cdxPropertyName.indexOf(':');
        if (firstSeparatorIndex < 0) {
            property.setPropertyName(cdxPropertyName);
        } else {
            property.setGroupName(cdxPropertyName.substring(0, firstSeparatorIndex));
            property.setPropertyName(cdxPropertyName.substring(firstSeparatorIndex + 1));
        }

        return property;
    }

    public static List<ServiceComponent> convertServices(final List<Service> cdxServices) {
        if (cdxServices.isEmpty()) {
            return Collections.emptyList();
        }
        return cdxServices.stream().map(ModelConverterProto::convertService).toList();
    }

    public static ServiceComponent convertService(final Service cdxService) {
        final var service = new ServiceComponent();
        service.setBomRef(useOrGenerateRandomBomRef(cdxService.getBomRef()));
        service.setProvider(convert(cdxService.getProvider()));
        service.setGroup(trimToNull(cdxService.getGroup()));
        service.setName(requireNonNullElse(trimToNull(cdxService.getName()), "-"));
        service.setVersion(trimToNull(cdxService.getVersion()));
        service.setDescription(trimToNull(cdxService.getDescription()));
        service.setAuthenticated(cdxService.getAuthenticated());
        service.setCrossesTrustBoundary(cdxService.getXTrustBoundary());
        service.setExternalReferences(convertExternalReferences(cdxService.getExternalReferencesList()));
        if (cdxService.hasProvider()) {
            service.setProvider(convertOrganizationalEntity(cdxService.getProvider()));
        }
        service.setData(convertDataClassification(cdxService.getDataList()));

        if (cdxService.getEndpointsCount() > 0) {
            service.setEndpoints(cdxService.getEndpointsList().toArray(new String[0]));
        }

        if (cdxService.getServicesCount() > 0) {
            final var children = new ArrayList<ServiceComponent>();
            for (final Service cdxChildService : cdxService.getServicesList()) {
                children.add(convertService(cdxChildService));
            }

            service.setChildren(children);
        }

        return service;
    }

    public static MultiValuedMap<String, String> convertDependencyGraph(final List<Dependency> cdxDependencies) {
        final var dependencyGraph = new HashSetValuedHashMap<String, String>();
        if (cdxDependencies.isEmpty()) {
            return dependencyGraph;
        }

        for (final Dependency cdxDependency : cdxDependencies) {
            if (cdxDependency.getDependenciesCount() == 0) {
                continue;
            }

            final List<String> directDependencies = cdxDependency.getDependenciesList().stream()
                    .map(Dependency::getRef).toList();
            dependencyGraph.putAll(cdxDependency.getRef(), directDependencies);
        }

        return dependencyGraph;
    }

    private static Optional<Classifier> convertClassifier(final Classification cdxComponentType) {
        var classifier = switch (cdxComponentType) {
                case CLASSIFICATION_APPLICATION -> Classifier.APPLICATION;
                case CLASSIFICATION_FRAMEWORK -> Classifier.FRAMEWORK;
                case CLASSIFICATION_LIBRARY -> Classifier.LIBRARY;
                case CLASSIFICATION_OPERATING_SYSTEM -> Classifier.OPERATING_SYSTEM;
                case CLASSIFICATION_DEVICE -> Classifier.DEVICE;
                case CLASSIFICATION_FILE -> Classifier.FILE;
                case CLASSIFICATION_CONTAINER -> Classifier.CONTAINER;
                case CLASSIFICATION_FIRMWARE -> Classifier.FIRMWARE;
                case CLASSIFICATION_DEVICE_DRIVER -> Classifier.DEVICE_DRIVER;
                case CLASSIFICATION_PLATFORM -> Classifier.PLATFORM;
                case CLASSIFICATION_MACHINE_LEARNING_MODEL -> Classifier.MACHINE_LEARNING_MODEL;
                case CLASSIFICATION_DATA -> Classifier.DATA;
                default -> null;
            };
        return Optional.ofNullable(classifier);
    }

    private static List<ExternalReference> convertExternalReferences(final List<org.cyclonedx.proto.v1_6.ExternalReference> cdxExternalReferences) {
        if (cdxExternalReferences.isEmpty()) {
            return null;
        }

        return cdxExternalReferences.stream()
                .map(cdxExternalReference -> {
                    final var externalReference = new ExternalReference();
                    externalReference.setType(mapExternalReferenceType(cdxExternalReference.getType()));
                    externalReference.setUrl(cdxExternalReference.getUrl());
                    externalReference.setComment(cdxExternalReference.getComment());
                    return externalReference;
                })
                .toList();
    }

    private static Type mapExternalReferenceType(ExternalReferenceType cdxExtReferenceType) {
        return switch (cdxExtReferenceType) {
            case EXTERNAL_REFERENCE_TYPE_OTHER -> Type.OTHER;
            case EXTERNAL_REFERENCE_TYPE_VCS -> Type.VCS;
            case EXTERNAL_REFERENCE_TYPE_ISSUE_TRACKER -> Type.ISSUE_TRACKER;
            case EXTERNAL_REFERENCE_TYPE_WEBSITE -> Type.WEBSITE;
            case EXTERNAL_REFERENCE_TYPE_ADVISORIES -> Type.ADVISORIES;
            case EXTERNAL_REFERENCE_TYPE_BOM -> Type.BOM;
            case EXTERNAL_REFERENCE_TYPE_MAILING_LIST -> Type.MAILING_LIST;
            case EXTERNAL_REFERENCE_TYPE_SOCIAL -> Type.SOCIAL;
            case EXTERNAL_REFERENCE_TYPE_CHAT -> Type.CHAT;
            case EXTERNAL_REFERENCE_TYPE_DOCUMENTATION -> Type.DOCUMENTATION;
            case EXTERNAL_REFERENCE_TYPE_SUPPORT -> Type.SUPPORT;
            case EXTERNAL_REFERENCE_TYPE_DISTRIBUTION -> Type.DISTRIBUTION;
            case EXTERNAL_REFERENCE_TYPE_LICENSE -> Type.LICENSE;
            case EXTERNAL_REFERENCE_TYPE_BUILD_META -> Type.BUILD_META;
            case EXTERNAL_REFERENCE_TYPE_BUILD_SYSTEM -> Type.BUILD_SYSTEM;
            case EXTERNAL_REFERENCE_TYPE_SECURITY_CONTACT -> Type.SECURITY_CONTACT;
            case EXTERNAL_REFERENCE_TYPE_ATTESTATION -> Type.ATTESTATION;
            case EXTERNAL_REFERENCE_TYPE_THREAT_MODEL -> Type.THREAT_MODEL;
            case EXTERNAL_REFERENCE_TYPE_ADVERSARY_MODEL -> Type.ADVERSARY_MODEL;
            case EXTERNAL_REFERENCE_TYPE_RISK_ASSESSMENT -> Type.RISK_ASSESSMENT;
            case EXTERNAL_REFERENCE_TYPE_DISTRIBUTION_INTAKE -> Type.DISTRIBUTION_INTAKE;
            case EXTERNAL_REFERENCE_TYPE_VULNERABILITY_ASSERTION -> Type.VULNERABILITY_ASSERTION;
            case EXTERNAL_REFERENCE_TYPE_EXPLOITABILITY_STATEMENT -> Type.EXPLOITABILITY_STATEMENT;
            case EXTERNAL_REFERENCE_TYPE_PENTEST_REPORT -> Type.PENTEST_REPORT;
            case EXTERNAL_REFERENCE_TYPE_STATIC_ANALYSIS_REPORT -> Type.STATIC_ANALYSIS_REPORT;
            case EXTERNAL_REFERENCE_TYPE_DYNAMIC_ANALYSIS_REPORT -> Type.DYNAMIC_ANALYSIS_REPORT;
            case EXTERNAL_REFERENCE_TYPE_RUNTIME_ANALYSIS_REPORT -> Type.RUNTIME_ANALYSIS_REPORT;
            case EXTERNAL_REFERENCE_TYPE_COMPONENT_ANALYSIS_REPORT -> Type.COMPONENT_ANALYSIS_REPORT;
            case EXTERNAL_REFERENCE_TYPE_MATURITY_REPORT -> Type.MATURITY_REPORT;
            case EXTERNAL_REFERENCE_TYPE_CERTIFICATION_REPORT -> Type.CERTIFICATION_REPORT;
            case EXTERNAL_REFERENCE_TYPE_QUALITY_METRICS -> Type.QUALITY_METRICS;
            case EXTERNAL_REFERENCE_TYPE_CODIFIED_INFRASTRUCTURE -> Type.CODIFIED_INFRASTRUCTURE;
            case EXTERNAL_REFERENCE_TYPE_MODEL_CARD -> Type.MODEL_CARD;
            case EXTERNAL_REFERENCE_TYPE_POAM -> Type.OTHER;
            case EXTERNAL_REFERENCE_TYPE_LOG -> Type.LOG;
            case EXTERNAL_REFERENCE_TYPE_CONFIGURATION -> Type.CONFIGURATION;
            case EXTERNAL_REFERENCE_TYPE_EVIDENCE -> Type.EVIDENCE;
            case EXTERNAL_REFERENCE_TYPE_FORMULATION -> Type.FORMULATION;
            case EXTERNAL_REFERENCE_TYPE_SOURCE_DISTRIBUTION -> Type.SOURCE_DISTRIBUTION;
            case EXTERNAL_REFERENCE_TYPE_ELECTRONIC_SIGNATURE -> Type.ELECTRONIC_SIGNATURE;
            case EXTERNAL_REFERENCE_TYPE_DIGITAL_SIGNATURE -> Type.DIGITAL_SIGNATURE;
            case EXTERNAL_REFERENCE_TYPE_RFC_9116 -> Type.RFC_9116;
            case UNRECOGNIZED -> null;
        };
    }

    public static OrganizationalEntity convertOrganizationalEntity(final org.cyclonedx.proto.v1_6.OrganizationalEntity cdxEntity) {

        final var entity = new OrganizationalEntity();
        entity.setName(cdxEntity.getName());

        if (cdxEntity.getUrlCount() > 0) {
            entity.setUrls(cdxEntity.getUrlList().toArray(new String[0]));
        }

        if (cdxEntity.getContactCount() > 0) {
            final var contacts = new ArrayList<OrganizationalContact>();
            for (final org.cyclonedx.proto.v1_6.OrganizationalContact cdxContact : cdxEntity.getContactList()) {
                final var contact = new OrganizationalContact();
                contact.setName(cdxContact.getName());
                contact.setEmail(cdxContact.getEmail());
                contact.setPhone(cdxContact.getPhone());
                contacts.add(contact);
            }
            entity.setContacts(contacts);
        }

        return entity;
    }

    private static List<DataClassification> convertDataClassification(final List<DataFlow> cdxData) {
        if (cdxData.isEmpty()) {
            return Collections.emptyList();
        }

        return cdxData.stream()
                .map(cdxDatum -> {
                    final var classification = new DataClassification();
                    classification.setName(cdxDatum.getValue());
                    classification.setDirection(mapDataFlowDirection(cdxDatum.getFlow()));
                    return classification;
                })
                .toList();
    }

    private static DataClassification.Direction mapDataFlowDirection(DataFlowDirection cdxDataFlowDirection) {
        return switch (cdxDataFlowDirection) {
            case DATA_FLOW_NULL, UNRECOGNIZED -> null;
            case DATA_FLOW_INBOUND -> DataClassification.Direction.INBOUND;
            case DATA_FLOW_OUTBOUND -> DataClassification.Direction.OUTBOUND;
            case DATA_FLOW_BI_DIRECTIONAL -> DataClassification.Direction.BI_DIRECTIONAL;
            case DATA_FLOW_UNKNOWN -> DataClassification.Direction.UNKNOWN;
        };
    }

    private static String useOrGenerateRandomBomRef(final String bomRef) {
        return Optional.ofNullable(bomRef)
                .map(StringUtils::trimToNull)
                .orElseGet(() -> UUID.randomUUID().toString());
    }
}
