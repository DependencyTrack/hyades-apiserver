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
import org.cyclonedx.model.BomReference;
import org.cyclonedx.model.Dependency;
import org.cyclonedx.model.Metadata;
import org.cyclonedx.model.Tool;
import org.cyclonedx.model.component.crypto.AlgorithmProperties;
import org.cyclonedx.model.component.crypto.CertificateProperties;
import org.cyclonedx.model.component.crypto.CryptoProperties;
import org.cyclonedx.model.component.crypto.CryptoRef;
import org.cyclonedx.model.component.crypto.ProtocolProperties;
import org.cyclonedx.model.component.crypto.RelatedCryptoMaterialProperties;
import org.cyclonedx.model.component.crypto.enums.Mechanism;
import org.cyclonedx.model.license.Expression;
import org.dependencytrack.model.AnalysisJustification;
import org.dependencytrack.model.AnalysisResponse;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.CipherSuite;
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentProperty;
import org.dependencytrack.model.CryptoAlgorithmProperties;
import org.dependencytrack.model.CryptoAssetProperties;
import org.dependencytrack.model.CryptoCertificateProperties;
import org.dependencytrack.model.CryptoProtocolProperties;
import org.dependencytrack.model.CryptoRelatedMaterialProperties;
import org.dependencytrack.model.DataClassification;
import org.dependencytrack.model.ExternalReference;
import org.dependencytrack.model.Ikev2Type;
import org.dependencytrack.model.OrganizationalContact;
import org.dependencytrack.model.OrganizationalEntity;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectMetadata;
import org.dependencytrack.model.SecuredBy;
import org.dependencytrack.model.ServiceComponent;
import org.dependencytrack.model.Tools;
import org.dependencytrack.parser.spdx.expression.SpdxExpressionParser;
import org.dependencytrack.parser.spdx.expression.model.SpdxExpression;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.function.Function;

import static java.util.Objects.requireNonNullElse;
import static org.apache.commons.lang3.StringUtils.isNotBlank;
import static org.apache.commons.lang3.StringUtils.trim;
import static org.apache.commons.lang3.StringUtils.trimToNull;
import static org.dependencytrack.util.PurlUtil.silentPurlCoordinatesOnly;
public class ModelConverter {

    private static final Logger LOGGER = Logger.getLogger(ModelConverter.class);

    /**
     * Private Constructor.
     */
    private ModelConverter() {
    }

    public static ProjectMetadata convertToProjectMetadata(final Metadata cdxMetadata) {
        if (cdxMetadata == null) {
            return null;
        }

        final var projectMetadata = new ProjectMetadata();
        projectMetadata.setSupplier(ModelConverter.convert(cdxMetadata.getSupplier()));
        projectMetadata.setAuthors(ModelConverter.convertCdxContacts(cdxMetadata.getAuthors()));

        final var toolComponents = new ArrayList<Component>();
        final var toolServices = new ArrayList<ServiceComponent>();
        if (cdxMetadata.getTools() != null) {
            cdxMetadata.getTools().stream().map(ModelConverter::convert).forEach(toolComponents::add);
        }
        if (cdxMetadata.getToolChoice() != null) {
            if (cdxMetadata.getToolChoice().getComponents() != null) {
                cdxMetadata.getToolChoice().getComponents().stream().map(ModelConverter::convertComponent).forEach(toolComponents::add);
            }
            if (cdxMetadata.getToolChoice().getServices() != null) {
                cdxMetadata.getToolChoice().getServices().stream().map(ModelConverter::convertService).forEach(toolServices::add);
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

    public static Project convertToProject(final org.cyclonedx.model.Metadata cdxMetadata) {
        if (cdxMetadata == null || cdxMetadata.getComponent() == null) {
            return null;
        }

        return convertToProject(cdxMetadata.getComponent());
    }

    public static Project convertToProject(final org.cyclonedx.model.Component cdxComponent) {
        final var project = new Project();
        project.setBomRef(useOrGenerateRandomBomRef(cdxComponent.getBomRef()));
        project.setPublisher(trimToNull(cdxComponent.getPublisher()));
        project.setSupplier(convert(cdxComponent.getSupplier()));
        project.setClassifier(convertClassifier(cdxComponent.getType()).orElse(Classifier.APPLICATION));
        project.setGroup(trimToNull(cdxComponent.getGroup()));
        project.setName(trimToNull(cdxComponent.getName()));
        project.setVersion(trimToNull(cdxComponent.getVersion()));
        project.setDescription(trimToNull(cdxComponent.getDescription()));
        project.setExternalReferences(convertExternalReferences(cdxComponent.getExternalReferences()));
        project.setSupplier(ModelConverter.convert(cdxComponent.getSupplier()));
        project.setManufacturer(ModelConverter.convert(cdxComponent.getManufacturer()));

        List<OrganizationalContact> contacts = new ArrayList<>();
        if(cdxComponent.getAuthor()!=null){
            contacts.add(new OrganizationalContact() {{
                setName(cdxComponent.getAuthor());
            }});
        }
        if(cdxComponent.getAuthors()!=null){
            contacts.addAll(convertCdxContacts(cdxComponent.getAuthors()));
        }
        project.setAuthors(contacts);

        if (cdxComponent.getPurl() != null) {
            try {
                final var purl = new PackageURL(cdxComponent.getPurl());
                project.setPurl(purl);
            } catch (MalformedPackageURLException e) {
                LOGGER.debug("Encountered invalid PURL", e);
            }
        }

        if (cdxComponent.getSwid() != null) {
            project.setSwidTagId(trimToNull(cdxComponent.getSwid().getTagId()));
        }

        return project;
    }

    public static List<Component> convertComponents(final List<org.cyclonedx.model.Component> cdxComponents) {
        if (cdxComponents == null || cdxComponents.isEmpty()) {
            return Collections.emptyList();
        }

        return cdxComponents.stream().map(ModelConverter::convertComponent).toList();
    }

    public static Component convertComponent(final org.cyclonedx.model.Component cdxComponent) {
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
        component.setExternalReferences(convertExternalReferences(cdxComponent.getExternalReferences()));
        component.setProperties(convertToComponentProperties(cdxComponent.getProperties()));

        List<OrganizationalContact> contacts = new ArrayList<>();
        if(cdxComponent.getAuthor()!=null){
            contacts.add(new OrganizationalContact() {{
                setName(cdxComponent.getAuthor());
            }});
        }
        if(cdxComponent.getAuthors()!=null){
            contacts.addAll(convertCdxContacts(cdxComponent.getAuthors()));
        }
        component.setAuthors(contacts);

        if (cdxComponent.getPurl() != null) {
            try {
                final var purl = new PackageURL(cdxComponent.getPurl());
                component.setPurl(purl);
                component.setPurlCoordinates(silentPurlCoordinatesOnly(purl));
            } catch (MalformedPackageURLException e) {
                LOGGER.debug("Encountered invalid PURL", e);
            }
        }

        if (cdxComponent.getSwid() != null) {
            component.setSwidTagId(trimToNull(cdxComponent.getSwid().getTagId()));
        }

        if (cdxComponent.getHashes() != null && !cdxComponent.getHashes().isEmpty()) {
            for (final org.cyclonedx.model.Hash cdxHash : cdxComponent.getHashes()) {
                final Consumer<String> hashSetter = switch (cdxHash.getAlgorithm().toLowerCase()) {
                    case "md5" -> component::setMd5;
                    case "sha-1" -> component::setSha1;
                    case "sha-256" -> component::setSha256;
                    case "sha-384" -> component::setSha384;
                    case "sha-512" -> component::setSha512;
                    case "sha3-256" -> component::setSha3_256;
                    case "sha3-384" -> component::setSha3_384;
                    case "sha3-512" -> component::setSha3_512;
                    case "blake2b-256" -> component::setBlake2b_256;
                    case "blake2b-384" -> component::setBlake2b_384;
                    case "blake2b-512" -> component::setBlake2b_512;
                    case "blake3" -> component::setBlake3;
                    default -> null;
                };
                if (hashSetter != null) {
                    hashSetter.accept(cdxHash.getValue());
                }
            }
        }

        final var licenseCandidates = new ArrayList<org.cyclonedx.model.License>();
        if (cdxComponent.getLicenses() != null) {
            if (cdxComponent.getLicenses().getLicenses() != null) {
                cdxComponent.getLicenses().getLicenses().stream()
                        .filter(license -> isNotBlank(license.getId()) || isNotBlank(license.getName()))
                        .peek(license -> {
                            // License text can be large, but we don't need it for further processing. Drop it.
                            license.setLicenseText(null);
                        })
                        .forEach(licenseCandidates::add);
            }

            final Expression licenseExpression = cdxComponent.getLicenses().getExpression();
            if (licenseExpression != null && isNotBlank(licenseExpression.getValue())) {
                // If the expression consists of just one license ID, add it as another option.
                final var expressionParser = new SpdxExpressionParser();
                final SpdxExpression expression = expressionParser.parse(licenseExpression.getValue());
                if (!SpdxExpression.INVALID.equals(expression)) {
                    component.setLicenseExpression(trim(licenseExpression.getValue()));

                    if (expression.getSpdxLicenseId() != null) {
                        final var expressionLicense = new org.cyclonedx.model.License();
                        expressionLicense.setId(expression.getSpdxLicenseId());
                        expressionLicense.setName(expression.getSpdxLicenseId());
                        licenseCandidates.add(expressionLicense);
                    }
                } else {
                    LOGGER.warn("""
                            Encountered invalid license expression "%s" for \
                            Component{group=%s, name=%s, version=%s, bomRef=%s}; Skipping\
                            """.formatted(cdxComponent.getLicenses().getExpression(), component.getGroup(),
                            component.getName(), component.getVersion(), component.getBomRef()));
                }
            }
        }
        component.setLicenseCandidates(licenseCandidates);

        if (cdxComponent.getComponents() != null && !cdxComponent.getComponents().isEmpty()) {
            final var children = new ArrayList<Component>();

            for (final org.cyclonedx.model.Component cdxChildComponent : cdxComponent.getComponents()) {
                children.add(convertComponent(cdxChildComponent));
            }

            component.setChildren(children);
        }

        if (cdxComponent.getCryptoProperties() != null) {
            CryptoProperties cryptoProperties = cdxComponent.getCryptoProperties();
            CryptoAssetProperties cryptoAssetProperties = new CryptoAssetProperties();

            cryptoAssetProperties.setAssetType(cryptoProperties.getAssetType());

            switch (cryptoAssetProperties.getAssetType()) {
                case ALGORITHM:
                    if (cryptoProperties.getAlgorithmProperties() != null) {
                        cryptoAssetProperties.setAlgorithmProperties(convert(cryptoProperties.getAlgorithmProperties()));
                    }
                    break;
                case CERTIFICATE:
                    if (cryptoProperties.getCertificateProperties() != null) {
                        cryptoAssetProperties.setCertificateProperties(convert(cryptoProperties.getCertificateProperties()));
                    }
                    break;
                case RELATED_CRYPTO_MATERIAL:
                    if (cryptoProperties.getRelatedCryptoMaterialProperties() != null) {
                        cryptoAssetProperties.setRelatedMaterialProperties(convert(cryptoProperties.getRelatedCryptoMaterialProperties()));
                    }
                    break;
                case PROTOCOL:
                    if (cryptoProperties.getProtocolProperties() != null) {
                        cryptoAssetProperties.setProtocolProperties(convert(cryptoProperties.getProtocolProperties()));
                    }
                    break;
                default:
                    break;
            }

            cryptoAssetProperties.setOid(cryptoProperties.getOid());
            component.setCryptoAssetProperties(cryptoAssetProperties);
        }

        return component;
    }

    private static CryptoAlgorithmProperties convert(AlgorithmProperties algorithmProperties) {
        CryptoAlgorithmProperties cap = new CryptoAlgorithmProperties();
        cap.setPrimitive(algorithmProperties.getPrimitive());
        cap.setParameterSetIdentifier(algorithmProperties.getParameterSetIdentifier());
        cap.setCurve(algorithmProperties.getCurve());
        cap.setExecutionEnvironment(algorithmProperties.getExecutionEnvironment());
        cap.setImplementationPlatform(algorithmProperties.getImplementationPlatform());
        cap.setCertificationLevel(algorithmProperties.getCertificationLevel());
        cap.setMode(algorithmProperties.getMode());
        cap.setPadding(algorithmProperties.getPadding());
        cap.setCryptoFunctions(algorithmProperties.getCryptoFunctions());
        cap.setClassicalSecurityLevel(algorithmProperties.getClassicalSecurityLevel());
        cap.setNistQuantumSecurityLevel(algorithmProperties.getNistQuantumSecurityLevel());
        return cap;
    }

    private static CryptoCertificateProperties convert(CertificateProperties certificateProperties) {
        CryptoCertificateProperties ccp = new CryptoCertificateProperties();
        ccp.setSubjectName(certificateProperties.getSubjectName());
        ccp.setIssuerName(certificateProperties.getIssuerName());
        ccp.setNotValidBefore(certificateProperties.getNotValidBefore());
        ccp.setNotValidAfter(certificateProperties.getNotValidAfter());
        ccp.setSignatureAlgorithmRef(certificateProperties.getSignatureAlgorithmRef());
        ccp.setSubjectPublicKeyRef(certificateProperties.getSubjectPublicKeyRef());
        ccp.setCertificateFormat(certificateProperties.getCertificateFormat());
        ccp.setCertificateExtension(certificateProperties.getCertificateExtension());
        return ccp;
    }

    private static CryptoRelatedMaterialProperties convert(RelatedCryptoMaterialProperties cryptoMaterialProperties) {
        CryptoRelatedMaterialProperties crp = new CryptoRelatedMaterialProperties();
        crp.setType(cryptoMaterialProperties.getType());
        crp.setIdentifier(cryptoMaterialProperties.getId());
        crp.setState(cryptoMaterialProperties.getState());
        crp.setAlgorithmRef(cryptoMaterialProperties.getAlgorithmRef());
        crp.setCreationDate(cryptoMaterialProperties.getCreationDate());
        crp.setActivationDate(cryptoMaterialProperties.getActivationDate());
        crp.setUpdateDate(cryptoMaterialProperties.getUpdateDate());
        crp.setExpirationDate(cryptoMaterialProperties.getExpirationDate());
        crp.setValue(cryptoMaterialProperties.getValue());
        crp.setSize(cryptoMaterialProperties.getSize());
        crp.setFormat(cryptoMaterialProperties.getFormat());
        if (cryptoMaterialProperties.getSecuredBy() != null) {
            SecuredBy securedBy = new SecuredBy();
            securedBy.setMechanism(Mechanism.valueOf(cryptoMaterialProperties.getSecuredBy().getMechanism().toUpperCase()));
            securedBy.setAlgorithmRef(cryptoMaterialProperties.getSecuredBy().getAlgorithmRef());
            crp.setSecuredBy(securedBy);
        }
        return crp;
    }

    private static CryptoProtocolProperties convert(ProtocolProperties protocolProperties) {
        CryptoProtocolProperties cpp = new CryptoProtocolProperties();
        cpp.setType(protocolProperties.getType());
        cpp.setVersion(protocolProperties.getVersion());

        if (protocolProperties.getCipherSuites() != null && !protocolProperties.getCipherSuites().isEmpty()) {
            final var suites = new ArrayList<CipherSuite>();
            for (final org.cyclonedx.model.component.crypto.CipherSuite cdxCipherSuite : protocolProperties.getCipherSuites()) {
                suites.add(convertCipherSuite(cdxCipherSuite));
            }
            cpp.setCipherSuites(suites);
        }

        if (protocolProperties.getIkev2TransformTypes() != null) {
            Map<String, CryptoRef> cxIkev2Types = protocolProperties.getIkev2TransformTypes();
            final List<Ikev2Type> ikev2Types = new ArrayList<>();
            for (Map.Entry<String, CryptoRef> e : cxIkev2Types.entrySet()) {
                Ikev2Type ikev2Type = new Ikev2Type();
                ikev2Type.setType(e.getKey());
                ikev2Type.setRefs(e.getValue().getRef());
                ikev2Types.add(ikev2Type);
            }
            cpp.setIkev2Types(ikev2Types);
        }

        if (protocolProperties.getCryptoRefArray() != null) {
            cpp.setCryptoRefs(protocolProperties.getCryptoRefArray().getRef());
        }

        return cpp;
    }

    private static CipherSuite convertCipherSuite(org.cyclonedx.model.component.crypto.CipherSuite cs) {
        CipherSuite modelCS = new CipherSuite();
        modelCS.setName(cs.getName());
        modelCS.setAlgorithms(cs.getAlgorithms());
        modelCS.setIdentifiers(cs.getIdentifiers());
        return modelCS;
    }


    private static Component convert(@SuppressWarnings("deprecation") final Tool tool) {
        if (tool == null) {
            return null;
        }

        final var component = new Component();
        if (tool.getVendor() != null && !tool.getVendor().isBlank()) {
            final var supplier = new OrganizationalEntity();
            supplier.setName(trimToNull(tool.getVendor()));
            component.setSupplier(supplier);
        }
        component.setName(trimToNull(tool.getName()));
        component.setVersion(trimToNull(tool.getVersion()));
        component.setExternalReferences(convertExternalReferences(tool.getExternalReferences()));

        if (tool.getHashes() != null && !tool.getHashes().isEmpty()) {
            for (final org.cyclonedx.model.Hash cdxHash : tool.getHashes()) {
                final Consumer<String> hashSetter = switch (cdxHash.getAlgorithm().toLowerCase()) {
                    case "md5" -> component::setMd5;
                    case "sha-1" -> component::setSha1;
                    case "sha-256" -> component::setSha256;
                    case "sha-384" -> component::setSha384;
                    case "sha-512" -> component::setSha512;
                    case "sha3-256" -> component::setSha3_256;
                    case "sha3-384" -> component::setSha3_384;
                    case "sha3-512" -> component::setSha3_512;
                    case "blake2b-256" -> component::setBlake2b_256;
                    case "blake2b-384" -> component::setBlake2b_384;
                    case "blake2b-512" -> component::setBlake2b_512;
                    case "blake3" -> component::setBlake3;
                    default -> null;
                };
                if (hashSetter != null) {
                    hashSetter.accept(cdxHash.getValue());
                }
            }
        }

        return component;
    }

    public static OrganizationalEntity convert(final org.cyclonedx.model.OrganizationalEntity cdxEntity) {
        if (cdxEntity == null) {
            return null;
        }

        final var dtEntity = new OrganizationalEntity();
        dtEntity.setName(StringUtils.trimToNull(cdxEntity.getName()));
        if (cdxEntity.getContacts() != null && !cdxEntity.getContacts().isEmpty()) {
            dtEntity.setContacts(cdxEntity.getContacts().stream().map(ModelConverter::convert).toList());
        }
        if (cdxEntity.getUrls() != null && !cdxEntity.getUrls().isEmpty()) {
            dtEntity.setUrls(cdxEntity.getUrls().toArray(new String[0]));
        }

        return dtEntity;
    }

    public static List<OrganizationalContact> convertCdxContacts(final List<org.cyclonedx.model.OrganizationalContact> cdxContacts) {
        if (cdxContacts == null) {
            return null;
        }

        return cdxContacts.stream().map(ModelConverter::convert).toList();
    }

    private static OrganizationalContact convert(final org.cyclonedx.model.OrganizationalContact cdxContact) {
        if (cdxContact == null) {
            return null;
        }

        final var dtContact = new OrganizationalContact();
        dtContact.setName(StringUtils.trimToNull(cdxContact.getName()));
        dtContact.setEmail(StringUtils.trimToNull(cdxContact.getEmail()));
        dtContact.setPhone(StringUtils.trimToNull(cdxContact.getPhone()));
        return dtContact;
    }

    private static List<ComponentProperty> convertToComponentProperties(final List<org.cyclonedx.model.Property> cdxProperties) {
        if (cdxProperties == null || cdxProperties.isEmpty()) {
            return Collections.emptyList();
        }

        final var identitiesSeen = new HashSet<ComponentProperty.Identity>();
        return cdxProperties.stream()
                .map(ModelConverter::convertToComponentProperty)
                .filter(Objects::nonNull)
                .filter(property -> identitiesSeen.add(new ComponentProperty.Identity(property)))
                .toList();
    }

    private static ComponentProperty convertToComponentProperty(final org.cyclonedx.model.Property cdxProperty) {
        if (cdxProperty == null) {
            return null;
        }

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

    public static List<ServiceComponent> convertServices(final List<org.cyclonedx.model.Service> cdxServices) {
        if (cdxServices == null || cdxServices.isEmpty()) {
            return Collections.emptyList();
        }

        return cdxServices.stream().map(ModelConverter::convertService).toList();
    }

    public static ServiceComponent convertService(final org.cyclonedx.model.Service cdxService) {
        final var service = new ServiceComponent();
        service.setBomRef(useOrGenerateRandomBomRef(cdxService.getBomRef()));
        service.setProvider(convert(cdxService.getProvider()));
        service.setGroup(trimToNull(cdxService.getGroup()));
        service.setName(requireNonNullElse(trimToNull(cdxService.getName()), "-"));
        service.setVersion(trimToNull(cdxService.getVersion()));
        service.setDescription(trimToNull(cdxService.getDescription()));
        service.setAuthenticated(cdxService.getAuthenticated());
        service.setCrossesTrustBoundary(cdxService.getxTrustBoundary());
        service.setExternalReferences(convertExternalReferences(cdxService.getExternalReferences()));
        service.setProvider(convertOrganizationalEntity(cdxService.getProvider()));
        service.setData(convertDataClassification(cdxService.getData()));

        if (cdxService.getEndpoints() != null && !cdxService.getEndpoints().isEmpty()) {
            service.setEndpoints(cdxService.getEndpoints().toArray(new String[0]));
        }

        if (cdxService.getServices() != null && !cdxService.getServices().isEmpty()) {
            final var children = new ArrayList<ServiceComponent>();

            for (final org.cyclonedx.model.Service cdxChildService : cdxService.getServices()) {
                children.add(convertService(cdxChildService));
            }

            service.setChildren(children);
        }

        return service;
    }

    public static MultiValuedMap<String, String> convertDependencyGraph(final List<Dependency> cdxDependencies) {
        final var dependencyGraph = new HashSetValuedHashMap<String, String>();
        if (cdxDependencies == null || cdxDependencies.isEmpty()) {
            return dependencyGraph;
        }

        for (final Dependency cdxDependency : cdxDependencies) {
            if (cdxDependency.getDependencies() == null || cdxDependency.getDependencies().isEmpty()) {
                continue;
            }

            final List<String> directDependencies = cdxDependency.getDependencies().stream()
                    .map(BomReference::getRef).toList();
            dependencyGraph.putAll(cdxDependency.getRef(), directDependencies);
        }

        return dependencyGraph;
    }

    private static Optional<Classifier> convertClassifier(final org.cyclonedx.model.Component.Type cdxComponentType) {
        return Optional.ofNullable(cdxComponentType)
                .map(Enum::name)
                .map(Classifier::valueOf);
    }

    private static List<ExternalReference> convertExternalReferences(final List<org.cyclonedx.model.ExternalReference> cdxExternalReferences) {
        if (cdxExternalReferences == null || cdxExternalReferences.isEmpty()) {
            return null;
        }

        return cdxExternalReferences.stream()
                .map(cdxExternalReference -> {
                    final var externalReference = new ExternalReference();
                    externalReference.setType(cdxExternalReference.getType());
                    externalReference.setUrl(cdxExternalReference.getUrl());
                    externalReference.setComment(cdxExternalReference.getComment());
                    return externalReference;
                })
                .toList();
    }

    private static OrganizationalEntity convertOrganizationalEntity(
            final org.cyclonedx.model.OrganizationalEntity cdxEntity) {
        if (cdxEntity == null) {
            return null;
        }

        final var entity = new OrganizationalEntity();
        entity.setName(cdxEntity.getName());

        if (cdxEntity.getUrls() != null && !cdxEntity.getUrls().isEmpty()) {
            entity.setUrls(cdxEntity.getUrls().toArray(new String[0]));
        }

        if (cdxEntity.getContacts() != null && !cdxEntity.getContacts().isEmpty()) {
            final var contacts = new ArrayList<OrganizationalContact>();
            for (final org.cyclonedx.model.OrganizationalContact cdxContact : cdxEntity.getContacts()) {
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

    private static List<DataClassification> convertDataClassification(final List<org.cyclonedx.model.ServiceData> cdxData) {
        if (cdxData == null || cdxData.isEmpty()) {
            return Collections.emptyList();
        }

        return cdxData.stream()
                .map(cdxDatum -> {
                    final var classification = new DataClassification();
                    classification.setName(cdxDatum.getClassification());
                    classification.setDirection(DataClassification.Direction.valueOf(cdxDatum.getFlow().name()));
                    return classification;
                })
                .toList();
    }

    private static String useOrGenerateRandomBomRef(final String bomRef) {
        return Optional.ofNullable(bomRef)
                .map(StringUtils::trimToNull)
                .orElseGet(() -> UUID.randomUUID().toString());
    }

    public static <T> List<T> flatten(final Collection<T> items,
                                      final Function<T, Collection<T>> childrenGetter,
                                      final BiConsumer<T, Collection<T>> childrenSetter) {
        final var result = new ArrayList<T>();
        if (items == null || items.isEmpty()) {
            return Collections.emptyList();
        }

        for (final T item : items) {
            final Collection<T> children = childrenGetter.apply(item);
            if (children != null) {
                result.addAll(flatten(children, childrenGetter, childrenSetter));
                childrenSetter.accept(item, null);
            }

            result.add(item);
        }

        return result;
    }

    public static AnalysisResponse convertCdxVulnAnalysisResponseToDtAnalysisResponse(final org.cyclonedx.model.vulnerability.Vulnerability.Analysis.Response cdxAnalysisResponse) {
        if (cdxAnalysisResponse == null) {
            return null;
        }
        switch (cdxAnalysisResponse) {
            case UPDATE:
                return AnalysisResponse.UPDATE;
            case CAN_NOT_FIX:
                return AnalysisResponse.CAN_NOT_FIX;
            case WILL_NOT_FIX:
                return AnalysisResponse.WILL_NOT_FIX;
            case ROLLBACK:
                return AnalysisResponse.ROLLBACK;
            case WORKAROUND_AVAILABLE:
                return AnalysisResponse.WORKAROUND_AVAILABLE;
            default:
                return AnalysisResponse.NOT_SET;
        }
    }

    public static AnalysisState convertCdxVulnAnalysisStateToDtAnalysisState(final org.cyclonedx.model.vulnerability.Vulnerability.Analysis.State cdxAnalysisState) {
        if (cdxAnalysisState == null) {
            return null;
        }
        switch (cdxAnalysisState) {
            case EXPLOITABLE:
                return AnalysisState.EXPLOITABLE;
            case FALSE_POSITIVE:
                return AnalysisState.FALSE_POSITIVE;
            case IN_TRIAGE:
                return AnalysisState.IN_TRIAGE;
            case NOT_AFFECTED:
                return AnalysisState.NOT_AFFECTED;
            case RESOLVED:
                return AnalysisState.RESOLVED;
            default:
                return AnalysisState.NOT_SET;
        }
    }


    public static AnalysisJustification convertCdxVulnAnalysisJustificationToDtAnalysisJustification(final org.cyclonedx.model.vulnerability.Vulnerability.Analysis.Justification cdxAnalysisJustification) {
        if (cdxAnalysisJustification == null) {
            return null;
        }
        switch (cdxAnalysisJustification) {
            case CODE_NOT_PRESENT:
                return AnalysisJustification.CODE_NOT_PRESENT;
            case CODE_NOT_REACHABLE:
                return AnalysisJustification.CODE_NOT_REACHABLE;
            case PROTECTED_AT_PERIMETER:
                return AnalysisJustification.PROTECTED_AT_PERIMETER;
            case PROTECTED_AT_RUNTIME:
                return AnalysisJustification.PROTECTED_AT_RUNTIME;
            case PROTECTED_BY_COMPILER:
                return AnalysisJustification.PROTECTED_BY_COMPILER;
            case PROTECTED_BY_MITIGATING_CONTROL:
                return AnalysisJustification.PROTECTED_BY_MITIGATING_CONTROL;
            case REQUIRES_CONFIGURATION:
                return AnalysisJustification.REQUIRES_CONFIGURATION;
            case REQUIRES_DEPENDENCY:
                return AnalysisJustification.REQUIRES_DEPENDENCY;
            case REQUIRES_ENVIRONMENT:
                return AnalysisJustification.REQUIRES_ENVIRONMENT;
            default:
                return AnalysisJustification.NOT_SET;
        }
    }
}
