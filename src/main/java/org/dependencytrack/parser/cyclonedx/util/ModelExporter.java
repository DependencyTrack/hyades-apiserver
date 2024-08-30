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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang3.StringUtils;
import org.cyclonedx.model.Hash;
import org.cyclonedx.model.LicenseChoice;
import org.cyclonedx.model.Swid;
import org.cyclonedx.model.component.crypto.AlgorithmProperties;
import org.cyclonedx.model.component.crypto.CertificateProperties;
import org.cyclonedx.model.component.crypto.CryptoProperties;
import org.cyclonedx.model.component.crypto.CryptoRef;
import org.cyclonedx.model.component.crypto.ProtocolProperties;
import org.cyclonedx.model.component.crypto.RelatedCryptoMaterialProperties;
import org.cyclonedx.model.component.crypto.SecuredBy;
import org.cyclonedx.model.license.Expression;
import org.dependencytrack.model.Analysis;
import org.dependencytrack.model.AnalysisJustification;
import org.dependencytrack.model.AnalysisResponse;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.CipherSuite;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.CryptoAlgorithmProperties;
import org.dependencytrack.model.CryptoAssetProperties;
import org.dependencytrack.model.CryptoCertificateProperties;
import org.dependencytrack.model.CryptoProtocolProperties;
import org.dependencytrack.model.CryptoRelatedMaterialProperties;
import org.dependencytrack.model.Cwe;
import org.dependencytrack.model.DataClassification;
import org.dependencytrack.model.ExternalReference;
import org.dependencytrack.model.Finding;
import org.dependencytrack.model.Ikev2Type;
import org.dependencytrack.model.Occurrence;
import org.dependencytrack.model.OrganizationalContact;
import org.dependencytrack.model.OrganizationalEntity;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ServiceComponent;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.parser.common.resolver.CweResolver;
import org.dependencytrack.parser.cyclonedx.CycloneDXExporter;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.util.DateUtil;
import org.dependencytrack.util.VulnerabilityUtil;

import alpine.model.IConfigProperty;

public class ModelExporter {

    private ModelExporter() {}

    public static org.cyclonedx.model.Metadata createMetadata(final Project project) {
        final org.cyclonedx.model.Metadata metadata = new org.cyclonedx.model.Metadata();
        final org.cyclonedx.model.Tool tool = new org.cyclonedx.model.Tool();
        tool.setVendor("OWASP");
        tool.setName(alpine.Config.getInstance().getApplicationName());
        tool.setVersion(alpine.Config.getInstance().getApplicationVersion());
        metadata.setTools(Collections.singletonList(tool));
        if (project != null) {
            final org.cyclonedx.model.Component cycloneComponent = new org.cyclonedx.model.Component();
            cycloneComponent.setBomRef(project.getUuid().toString());
            cycloneComponent.setAuthor(StringUtils.trimToNull(convertContactsToString(project.getAuthors())));
            cycloneComponent.setPublisher(StringUtils.trimToNull(project.getPublisher()));
            cycloneComponent.setGroup(StringUtils.trimToNull(project.getGroup()));
            cycloneComponent.setName(StringUtils.trimToNull(project.getName()));
            if (StringUtils.trimToNull(project.getVersion()) == null) {
                cycloneComponent.setVersion("SNAPSHOT"); // Version is required per CycloneDX spec
            } else {
                cycloneComponent.setVersion(StringUtils.trimToNull(project.getVersion()));
            }
            cycloneComponent.setDescription(StringUtils.trimToNull(project.getDescription()));
            cycloneComponent.setCpe(StringUtils.trimToNull(project.getCpe()));
            if (project.getPurl() != null) {
                cycloneComponent.setPurl(StringUtils.trimToNull(project.getPurl().canonicalize()));
            }
            if (StringUtils.trimToNull(project.getSwidTagId()) != null) {
                final Swid swid = new Swid();
                swid.setTagId(StringUtils.trimToNull(project.getSwidTagId()));
                swid.setName(StringUtils.trimToNull(project.getName()));
                swid.setVersion(StringUtils.trimToNull(project.getVersion()));
                cycloneComponent.setSwid(swid);
            }
            if (project.getClassifier() != null) {
                cycloneComponent.setType(org.cyclonedx.model.Component.Type.valueOf(project.getClassifier().name()));
            } else {
                cycloneComponent.setType(org.cyclonedx.model.Component.Type.LIBRARY);
            }
            if (project.getExternalReferences() != null && !project.getExternalReferences().isEmpty()) {
                List<org.cyclonedx.model.ExternalReference> references = new ArrayList<>();
                project.getExternalReferences().forEach(externalReference -> {
                    org.cyclonedx.model.ExternalReference ref = new org.cyclonedx.model.ExternalReference();
                    ref.setUrl(externalReference.getUrl());
                    ref.setType(externalReference.getType());
                    ref.setComment(externalReference.getComment());
                    references.add(ref);
                });
                cycloneComponent.setExternalReferences(references);
            }
            cycloneComponent.setSupplier(convert(project.getSupplier()));
            // NB: Project properties are currently used to configure integrations
            // such as Defect Dojo. They can also contain encrypted values that most
            // definitely are not safe to share. Before we can include project properties
            // in BOM exports, we need a filtering mechanism.
            // cycloneComponent.setProperties(convert(project.getProperties()));
            cycloneComponent.setManufacturer(convert(project.getManufacturer()));
            metadata.setComponent(cycloneComponent);

            if (project.getMetadata() != null) {
                metadata.setAuthors(convertContacts(project.getMetadata().getAuthors()));
                metadata.setSupplier(convert(project.getMetadata().getSupplier()));
            }
        }
        return metadata;
    }

    public static org.cyclonedx.model.Service convert(final QueryManager qm, final ServiceComponent service) {
        final org.cyclonedx.model.Service cycloneService = new org.cyclonedx.model.Service();
        cycloneService.setBomRef(service.getUuid().toString());
        cycloneService.setProvider(convert(service.getProvider()));
        cycloneService.setProvider(convert(service.getProvider()));
        cycloneService.setGroup(StringUtils.trimToNull(service.getGroup()));
        cycloneService.setName(StringUtils.trimToNull(service.getName()));
        cycloneService.setVersion(StringUtils.trimToNull(service.getVersion()));
        cycloneService.setDescription(StringUtils.trimToNull(service.getDescription()));
        if (service.getEndpoints() != null && service.getEndpoints().length > 0) {
            cycloneService.setEndpoints(Arrays.asList(service.getEndpoints().clone()));
        }
        cycloneService.setAuthenticated(service.getAuthenticated());
        cycloneService.setxTrustBoundary(service.getCrossesTrustBoundary());
        if (service.getData() != null && !service.getData().isEmpty()) {
            for (DataClassification dc : service.getData()) {
                org.cyclonedx.model.ServiceData sd = new org.cyclonedx.model.ServiceData(dc.getDirection().name(), dc.getName());
                cycloneService.addServiceData(sd);
            }
        }
        if (service.getExternalReferences() != null && !service.getExternalReferences().isEmpty()) {
            for (ExternalReference ref : service.getExternalReferences()) {
                org.cyclonedx.model.ExternalReference cycloneRef = new org.cyclonedx.model.ExternalReference();
                cycloneRef.setType(ref.getType());
                cycloneRef.setUrl(ref.getUrl());
                cycloneRef.setComment(ref.getComment());
                cycloneService.addExternalReference(cycloneRef);
            }
        }
        /* TODO: Add when services support licenses (after component license refactor)
        if (component.getResolvedLicense() != null) {
            final org.cyclonedx.model.License license = new org.cyclonedx.model.License();
            license.setId(component.getResolvedLicense().getLicenseId());
            final LicenseChoice licenseChoice = new LicenseChoice();
            licenseChoice.addLicense(license);
            cycloneComponent.setLicenses(licenseChoice);
        } else if (component.getLicense() != null) {
            final org.cyclonedx.model.License license = new org.cyclonedx.model.License();
            license.setName(component.getLicense());
            final LicenseChoice licenseChoice = new LicenseChoice();
            licenseChoice.addLicense(license);
            cycloneComponent.setLicenses(licenseChoice);
        }
        */

        /*
        TODO: Assemble child/parent hierarchy. Components come in as flat, resolved dependencies.
         */
        /*
        if (component.getChildren() != null && component.getChildren().size() > 0) {
            final List<org.cyclonedx.model.Component> components = new ArrayList<>();
            final Component[] children = component.getChildren().toArray(new Component[0]);
            for (Component child : children) {
                components.add(convert(qm, child));
            }
            if (children.length > 0) {
                cycloneComponent.setComponents(components);
            }
        }
        */
        return cycloneService;
    }

    private static <T extends IConfigProperty> List<org.cyclonedx.model.Property> convert(final Collection<T> dtProperties) {
        if (dtProperties == null || dtProperties.isEmpty()) {
            return Collections.emptyList();
        }

        final List<org.cyclonedx.model.Property> cdxProperties = new ArrayList<>();
        for (final T dtProperty : dtProperties) {
            if (dtProperty.getPropertyType() == IConfigProperty.PropertyType.ENCRYPTEDSTRING) {
                // We treat encrypted properties as internal.
                // They shall not be leaked when exporting.
                continue;
            }

            final var cdxProperty = new org.cyclonedx.model.Property();
            if (dtProperty.getGroupName() == null) {
                cdxProperty.setName(dtProperty.getPropertyName());
            } else {
                cdxProperty.setName("%s:%s".formatted(dtProperty.getGroupName(), dtProperty.getPropertyName()));
            }
            cdxProperty.setValue(dtProperty.getPropertyValue());
            cdxProperties.add(cdxProperty);
        }

        return cdxProperties;
    }

    private static org.cyclonedx.model.vulnerability.Vulnerability.Rating.Severity convertDtSeverityToCdxSeverity(final Severity severity) {
        switch (severity) {
            case CRITICAL:
                return org.cyclonedx.model.vulnerability.Vulnerability.Rating.Severity.CRITICAL;
            case HIGH:
                return org.cyclonedx.model.vulnerability.Vulnerability.Rating.Severity.HIGH;
            case MEDIUM:
                return org.cyclonedx.model.vulnerability.Vulnerability.Rating.Severity.MEDIUM;
            case LOW:
                return org.cyclonedx.model.vulnerability.Vulnerability.Rating.Severity.LOW;
            default:
                return org.cyclonedx.model.vulnerability.Vulnerability.Rating.Severity.UNKNOWN;
        }
    }

    private static org.cyclonedx.model.vulnerability.Vulnerability.Source convertDtVulnSourceToCdxVulnSource(final Vulnerability.Source vulnSource) {
        org.cyclonedx.model.vulnerability.Vulnerability.Source cdxSource = new org.cyclonedx.model.vulnerability.Vulnerability.Source();
        cdxSource.setName(vulnSource.name());
        switch (vulnSource) {
            case NVD:
                cdxSource.setUrl("https://nvd.nist.gov/");
                break;
            case NPM:
                cdxSource.setUrl("https://www.npmjs.com/");
                break;
            case GITHUB:
                cdxSource.setUrl("https://github.com/advisories");
                break;
            case VULNDB:
                cdxSource.setUrl("https://vulndb.cyberriskanalytics.com/");
                break;
            case OSSINDEX:
                cdxSource.setUrl("https://ossindex.sonatype.org/");
                break;
            case RETIREJS:
                cdxSource.setUrl("https://github.com/RetireJS/retire.js");
                break;
        }
        return cdxSource;
    }

    public static String convertContactsToString(List<OrganizationalContact> authors) {
        if (authors == null || authors.isEmpty()) {
            return "";
        }
        StringBuilder stringBuilder = new StringBuilder();
        for (OrganizationalContact author : authors) {
            if (author != null && author.getName() != null) {
                stringBuilder.append(author.getName()).append(", ");
            }
        }
        //remove trailing comma and space
        if (stringBuilder.length() > 0) {
            stringBuilder.setLength(stringBuilder.length() - 2);
        }
        return stringBuilder.toString();
    }

    private static org.cyclonedx.model.OrganizationalEntity convert(final OrganizationalEntity dtEntity) {
        if (dtEntity == null) {
            return null;
        }

        final var cdxEntity = new org.cyclonedx.model.OrganizationalEntity();
        cdxEntity.setName(StringUtils.trimToNull(dtEntity.getName()));
        if (dtEntity.getContacts() != null && !dtEntity.getContacts().isEmpty()) {
            cdxEntity.setContacts(dtEntity.getContacts().stream().map(ModelExporter::convert).toList());
        }
        if (dtEntity.getUrls() != null && dtEntity.getUrls().length > 0) {
            cdxEntity.setUrls(Arrays.stream(dtEntity.getUrls()).toList());
        }

        return cdxEntity;
    }

    private static List<org.cyclonedx.model.OrganizationalContact> convertContacts(final List<OrganizationalContact> dtContacts) {
        if (dtContacts == null) {
            return null;
        }

        return dtContacts.stream().map(ModelExporter::convert).toList();
    }

    private static org.cyclonedx.model.OrganizationalContact convert(final OrganizationalContact dtContact) {
        if (dtContact == null) {
            return null;
        }

        final var cdxContact = new org.cyclonedx.model.OrganizationalContact();
        cdxContact.setName(StringUtils.trimToNull(dtContact.getName()));
        cdxContact.setEmail(StringUtils.trimToNull(dtContact.getEmail()));
        cdxContact.setPhone(StringUtils.trimToNull(cdxContact.getPhone()));
        return cdxContact;
    }

    private static org.cyclonedx.model.vulnerability.Vulnerability.Analysis.Response convertDtVulnAnalysisResponseToCdxAnalysisResponse(final AnalysisResponse analysisResponse) {
        if (analysisResponse == null) {
            return null;
        }
        switch (analysisResponse) {
            case UPDATE:
                return org.cyclonedx.model.vulnerability.Vulnerability.Analysis.Response.UPDATE;
            case CAN_NOT_FIX:
                return org.cyclonedx.model.vulnerability.Vulnerability.Analysis.Response.CAN_NOT_FIX;
            case WILL_NOT_FIX:
                return org.cyclonedx.model.vulnerability.Vulnerability.Analysis.Response.WILL_NOT_FIX;
            case ROLLBACK:
                return org.cyclonedx.model.vulnerability.Vulnerability.Analysis.Response.ROLLBACK;
            case WORKAROUND_AVAILABLE:
                return org.cyclonedx.model.vulnerability.Vulnerability.Analysis.Response.WORKAROUND_AVAILABLE;
            default:
                return null;
        }
    }

    private static org.cyclonedx.model.vulnerability.Vulnerability.Analysis.State convertDtVulnAnalysisStateToCdxAnalysisState(final AnalysisState analysisState) {
        if (analysisState == null) {
            return null;
        }
        switch (analysisState) {
            case EXPLOITABLE:
                return org.cyclonedx.model.vulnerability.Vulnerability.Analysis.State.EXPLOITABLE;
            case FALSE_POSITIVE:
                return org.cyclonedx.model.vulnerability.Vulnerability.Analysis.State.FALSE_POSITIVE;
            case IN_TRIAGE:
                return org.cyclonedx.model.vulnerability.Vulnerability.Analysis.State.IN_TRIAGE;
            case NOT_AFFECTED:
                return org.cyclonedx.model.vulnerability.Vulnerability.Analysis.State.NOT_AFFECTED;
            case RESOLVED:
                return org.cyclonedx.model.vulnerability.Vulnerability.Analysis.State.RESOLVED;
            default:
                return null;
        }
    }

    private static org.cyclonedx.model.vulnerability.Vulnerability.Analysis.Justification convertDtVulnAnalysisJustificationToCdxAnalysisJustification(final AnalysisJustification analysisJustification) {
        if (analysisJustification == null) {
            return null;
        }
        switch (analysisJustification) {
            case CODE_NOT_PRESENT:
                return org.cyclonedx.model.vulnerability.Vulnerability.Analysis.Justification.CODE_NOT_PRESENT;
            case CODE_NOT_REACHABLE:
                return org.cyclonedx.model.vulnerability.Vulnerability.Analysis.Justification.CODE_NOT_REACHABLE;
            case PROTECTED_AT_PERIMETER:
                return org.cyclonedx.model.vulnerability.Vulnerability.Analysis.Justification.PROTECTED_AT_PERIMETER;
            case PROTECTED_AT_RUNTIME:
                return org.cyclonedx.model.vulnerability.Vulnerability.Analysis.Justification.PROTECTED_AT_RUNTIME;
            case PROTECTED_BY_COMPILER:
                return org.cyclonedx.model.vulnerability.Vulnerability.Analysis.Justification.PROTECTED_BY_COMPILER;
            case PROTECTED_BY_MITIGATING_CONTROL:
                return org.cyclonedx.model.vulnerability.Vulnerability.Analysis.Justification.PROTECTED_BY_MITIGATING_CONTROL;
            case REQUIRES_CONFIGURATION:
                return org.cyclonedx.model.vulnerability.Vulnerability.Analysis.Justification.REQUIRES_CONFIGURATION;
            case REQUIRES_DEPENDENCY:
                return org.cyclonedx.model.vulnerability.Vulnerability.Analysis.Justification.REQUIRES_DEPENDENCY;
            case REQUIRES_ENVIRONMENT:
                return org.cyclonedx.model.vulnerability.Vulnerability.Analysis.Justification.REQUIRES_ENVIRONMENT;
            default:
                return null;
        }
    }

    public static org.cyclonedx.model.vulnerability.Vulnerability convert(final QueryManager qm, final CycloneDXExporter.Variant variant,
                                                                          final Finding finding) {
        final Component component = qm.getObjectByUuid(Component.class, (String) finding.getComponent().get("uuid"));
        final Project project = component.getProject();
        final Vulnerability vulnerability = qm.getObjectByUuid(Vulnerability.class, (String) finding.getVulnerability().get("uuid"));

        final org.cyclonedx.model.vulnerability.Vulnerability cdxVulnerability = new org.cyclonedx.model.vulnerability.Vulnerability();
        cdxVulnerability.setBomRef(vulnerability.getUuid().toString());
        cdxVulnerability.setId(vulnerability.getVulnId());
        // Add the vulnerability source
        org.cyclonedx.model.vulnerability.Vulnerability.Source cdxSource = new org.cyclonedx.model.vulnerability.Vulnerability.Source();
        cdxSource.setName(vulnerability.getSource());
        cdxVulnerability.setSource(convertDtVulnSourceToCdxVulnSource(Vulnerability.Source.valueOf(vulnerability.getSource())));
        if (vulnerability.getCvssV2BaseScore() != null) {
            org.cyclonedx.model.vulnerability.Vulnerability.Rating rating = new org.cyclonedx.model.vulnerability.Vulnerability.Rating();
            rating.setSource(convertDtVulnSourceToCdxVulnSource(Vulnerability.Source.valueOf(vulnerability.getSource())));
            rating.setMethod(org.cyclonedx.model.vulnerability.Vulnerability.Rating.Method.CVSSV2);
            rating.setScore(vulnerability.getCvssV2BaseScore().doubleValue());
            rating.setVector(vulnerability.getCvssV2Vector());
            if (rating.getScore() >= 7.0) {
                rating.setSeverity(org.cyclonedx.model.vulnerability.Vulnerability.Rating.Severity.HIGH);
            } else if (rating.getScore() >= 4.0) {
                rating.setSeverity(org.cyclonedx.model.vulnerability.Vulnerability.Rating.Severity.MEDIUM);
            } else {
                rating.setSeverity(org.cyclonedx.model.vulnerability.Vulnerability.Rating.Severity.LOW);
            }
            cdxVulnerability.addRating(rating);
        }
        if (vulnerability.getCvssV3BaseScore() != null) {
            org.cyclonedx.model.vulnerability.Vulnerability.Rating rating = new org.cyclonedx.model.vulnerability.Vulnerability.Rating();
            rating.setSource(convertDtVulnSourceToCdxVulnSource(Vulnerability.Source.valueOf(vulnerability.getSource())));
            if (vulnerability.getCvssV3Vector() != null && vulnerability.getCvssV3Vector().contains("CVSS:3.0")) {
                rating.setMethod(org.cyclonedx.model.vulnerability.Vulnerability.Rating.Method.CVSSV3);
            } else {
                rating.setMethod(org.cyclonedx.model.vulnerability.Vulnerability.Rating.Method.CVSSV31);
            }
            rating.setScore(vulnerability.getCvssV3BaseScore().doubleValue());
            rating.setVector(vulnerability.getCvssV3Vector());
            if (rating.getScore() >= 9.0) {
                rating.setSeverity(org.cyclonedx.model.vulnerability.Vulnerability.Rating.Severity.CRITICAL);
            } else if (rating.getScore() >= 7.0) {
                rating.setSeverity(org.cyclonedx.model.vulnerability.Vulnerability.Rating.Severity.HIGH);
            } else if (rating.getScore() >= 4.0) {
                rating.setSeverity(org.cyclonedx.model.vulnerability.Vulnerability.Rating.Severity.MEDIUM);
            } else {
                rating.setSeverity(org.cyclonedx.model.vulnerability.Vulnerability.Rating.Severity.LOW);
            }
            cdxVulnerability.addRating(rating);
        }
        if (vulnerability.getOwaspRRLikelihoodScore() != null && vulnerability.getOwaspRRTechnicalImpactScore() != null && vulnerability.getOwaspRRBusinessImpactScore() != null) {
            org.cyclonedx.model.vulnerability.Vulnerability.Rating rating = new org.cyclonedx.model.vulnerability.Vulnerability.Rating();
            rating.setSeverity(convertDtSeverityToCdxSeverity(VulnerabilityUtil.normalizedOwaspRRScore(vulnerability.getOwaspRRLikelihoodScore().doubleValue(), vulnerability.getOwaspRRTechnicalImpactScore().doubleValue(), vulnerability.getOwaspRRBusinessImpactScore().doubleValue())));
            rating.setSource(convertDtVulnSourceToCdxVulnSource(Vulnerability.Source.valueOf(vulnerability.getSource())));
            rating.setMethod(org.cyclonedx.model.vulnerability.Vulnerability.Rating.Method.OWASP);
            rating.setVector(vulnerability.getOwaspRRVector());
            cdxVulnerability.addRating(rating);
        }
        if (vulnerability.getCvssV2BaseScore() == null && vulnerability.getCvssV3BaseScore() == null && vulnerability.getOwaspRRLikelihoodScore() == null) {
            org.cyclonedx.model.vulnerability.Vulnerability.Rating rating = new org.cyclonedx.model.vulnerability.Vulnerability.Rating();
            rating.setSeverity(convertDtSeverityToCdxSeverity(vulnerability.getSeverity()));
            rating.setSource(convertDtVulnSourceToCdxVulnSource(Vulnerability.Source.valueOf(vulnerability.getSource())));
            rating.setMethod(org.cyclonedx.model.vulnerability.Vulnerability.Rating.Method.OTHER);
            cdxVulnerability.addRating(rating);
        }
        if (vulnerability.getCwes() != null) {
            for (final Integer cweId : vulnerability.getCwes()) {
                final Cwe cwe = CweResolver.getInstance().lookup(cweId);
                if (cwe != null) {
                    cdxVulnerability.addCwe(cwe.getCweId());
                }
            }
        }
        cdxVulnerability.setDescription(vulnerability.getDescription());
        cdxVulnerability.setRecommendation(vulnerability.getRecommendation());
        cdxVulnerability.setCreated(vulnerability.getCreated());
        cdxVulnerability.setPublished(vulnerability.getPublished());
        cdxVulnerability.setUpdated(vulnerability.getUpdated());

        if (CycloneDXExporter.Variant.INVENTORY_WITH_VULNERABILITIES == variant || CycloneDXExporter.Variant.VDR == variant) {
            final List<org.cyclonedx.model.vulnerability.Vulnerability.Affect> affects = new ArrayList<>();
            final org.cyclonedx.model.vulnerability.Vulnerability.Affect affect = new org.cyclonedx.model.vulnerability.Vulnerability.Affect();
            affect.setRef(component.getUuid().toString());
            affects.add(affect);
            cdxVulnerability.setAffects(affects);
        } else if (CycloneDXExporter.Variant.VEX == variant && project != null) {
            final List<org.cyclonedx.model.vulnerability.Vulnerability.Affect> affects = new ArrayList<>();
            final org.cyclonedx.model.vulnerability.Vulnerability.Affect affect = new org.cyclonedx.model.vulnerability.Vulnerability.Affect();
            affect.setRef(project.getUuid().toString());
            affects.add(affect);
            cdxVulnerability.setAffects(affects);
        }

        if (CycloneDXExporter.Variant.VEX == variant || CycloneDXExporter.Variant.VDR == variant) {
            final Analysis analysis = qm.getAnalysis(
                    qm.getObjectByUuid(Component.class, component.getUuid()),
                    qm.getObjectByUuid(Vulnerability.class, vulnerability.getUuid())
            );
            if (analysis != null) {
                final org.cyclonedx.model.vulnerability.Vulnerability.Analysis cdxAnalysis = new org.cyclonedx.model.vulnerability.Vulnerability.Analysis();
                if (analysis.getAnalysisResponse() != null) {
                    final org.cyclonedx.model.vulnerability.Vulnerability.Analysis.Response response = convertDtVulnAnalysisResponseToCdxAnalysisResponse(analysis.getAnalysisResponse());
                    if (response != null) {
                        List<org.cyclonedx.model.vulnerability.Vulnerability.Analysis.Response> responses = new ArrayList<>();
                        responses.add(response);
                        cdxAnalysis.setResponses(responses);
                    }
                }
                if (analysis.getAnalysisState() != null) {
                    cdxAnalysis.setState(convertDtVulnAnalysisStateToCdxAnalysisState(analysis.getAnalysisState()));
                }
                if (analysis.getAnalysisJustification() != null) {
                    cdxAnalysis.setJustification(convertDtVulnAnalysisJustificationToCdxAnalysisJustification(analysis.getAnalysisJustification()));
                }
                cdxAnalysis.setDetail(StringUtils.trimToNull(analysis.getAnalysisDetails()));
                cdxVulnerability.setAnalysis(cdxAnalysis);
            }
        }

        return cdxVulnerability;
    }

    public static List<org.cyclonedx.model.vulnerability.Vulnerability> generateVulnerabilities(final QueryManager qm, final CycloneDXExporter.Variant variant, final List<Finding> findings) {
        if (findings == null) {
            return Collections.emptyList();
        }
        final var vulnerabilitiesSeen = new HashSet<org.cyclonedx.model.vulnerability.Vulnerability>();
        return findings.stream()
            .map(finding -> convert(qm, variant, finding))
            .filter(vulnerabilitiesSeen::add)
            .toList();
    }

    public static org.cyclonedx.model.Component convert(final QueryManager qm, final Component component) {
        final org.cyclonedx.model.Component cycloneComponent = new org.cyclonedx.model.Component();
        cycloneComponent.setBomRef(component.getUuid().toString());
        cycloneComponent.setGroup(StringUtils.trimToNull(component.getGroup()));
        cycloneComponent.setName(StringUtils.trimToNull(component.getName()));
        cycloneComponent.setVersion(StringUtils.trimToNull(component.getVersion()));
        cycloneComponent.setDescription(StringUtils.trimToNull(component.getDescription()));
        cycloneComponent.setCopyright(StringUtils.trimToNull(component.getCopyright()));
        cycloneComponent.setCpe(StringUtils.trimToNull(component.getCpe()));
        cycloneComponent.setAuthor(StringUtils.trimToNull(convertContactsToString(component.getAuthors())));
        cycloneComponent.setSupplier(convert(component.getSupplier()));
        cycloneComponent.setProperties(convert(component.getProperties()));

        if (component.getSwidTagId() != null) {
            final Swid swid = new Swid();
            swid.setTagId(component.getSwidTagId());
            cycloneComponent.setSwid(swid);
        }

        if (component.getPurl() != null) {
            cycloneComponent.setPurl(component.getPurl().canonicalize());
        }

        if (component.getClassifier() != null) {
            cycloneComponent.setType(org.cyclonedx.model.Component.Type.valueOf(component.getClassifier().name()));
        } else {
            cycloneComponent.setType(org.cyclonedx.model.Component.Type.LIBRARY);
        }

        if (component.getMd5() != null) {
            cycloneComponent.addHash(new Hash(Hash.Algorithm.MD5, component.getMd5()));
        }
        if (component.getSha1() != null) {
            cycloneComponent.addHash(new Hash(Hash.Algorithm.SHA1, component.getSha1()));
        }
        if (component.getSha256() != null) {
            cycloneComponent.addHash(new Hash(Hash.Algorithm.SHA_256, component.getSha256()));
        }
        if (component.getSha512() != null) {
            cycloneComponent.addHash(new Hash(Hash.Algorithm.SHA_512, component.getSha512()));
        }
        if (component.getSha3_256() != null) {
            cycloneComponent.addHash(new Hash(Hash.Algorithm.SHA3_256, component.getSha3_256()));
        }
        if (component.getSha3_512() != null) {
            cycloneComponent.addHash(new Hash(Hash.Algorithm.SHA3_512, component.getSha3_512()));
        }

        final LicenseChoice licenses = new LicenseChoice();
        if (component.getResolvedLicense() != null) {
            final org.cyclonedx.model.License license = new org.cyclonedx.model.License();
            if (!component.getResolvedLicense().isCustomLicense()) {
                license.setId(component.getResolvedLicense().getLicenseId());
            } else {
                license.setName(component.getResolvedLicense().getName());
            }
            license.setUrl(component.getLicenseUrl());
            licenses.addLicense(license);
            cycloneComponent.setLicenses(licenses);
        } else if (component.getLicense() != null) {
            final org.cyclonedx.model.License license = new org.cyclonedx.model.License();
            license.setName(component.getLicense());
            license.setUrl(component.getLicenseUrl());
            licenses.addLicense(license);
            cycloneComponent.setLicenses(licenses);
        } else if (StringUtils.isNotEmpty(component.getLicenseUrl())) {
            final org.cyclonedx.model.License license = new org.cyclonedx.model.License();
            license.setUrl(component.getLicenseUrl());
            licenses.addLicense(license);
            cycloneComponent.setLicenses(licenses);
        }
        if (component.getLicenseExpression() != null) {
            final var licenseExpression = new Expression();
            licenseExpression.setValue(component.getLicenseExpression());
            licenses.setExpression(licenseExpression);
            cycloneComponent.setLicenses(licenses);
        }

        if (component.getCryptoAssetProperties() != null) {
            CryptoAssetProperties cryptoAssetProperties = component.getCryptoAssetProperties();
            CryptoProperties cryptoProperties = new CryptoProperties();

            cryptoProperties.setAssetType(cryptoAssetProperties.getAssetType());

            switch (cryptoAssetProperties.getAssetType()) {
                case ALGORITHM:
                    if (cryptoAssetProperties.getAlgorithmProperties() != null) {
                        cryptoProperties.setAlgorithmProperties(convert(cryptoAssetProperties.getAlgorithmProperties()));
                    }
                    break;
                case CERTIFICATE:
                    if (cryptoAssetProperties.getCertificateProperties() != null) {
                        cryptoProperties.setCertificateProperties(convert(cryptoAssetProperties.getCertificateProperties()));
                    }
                    break;
                case RELATED_CRYPTO_MATERIAL:
                    if (cryptoAssetProperties.getRelatedMaterialProperties() != null) {
                        cryptoProperties.setRelatedCryptoMaterialProperties(convert(cryptoAssetProperties.getRelatedMaterialProperties()));
                    }
                    break;
                case PROTOCOL:
                    if (cryptoAssetProperties.getProtocolProperties() != null) {
                        cryptoProperties.setProtocolProperties(convert(cryptoAssetProperties.getProtocolProperties()));
                    }
                    break;
                default:
                    break;
            }

            cryptoProperties.setOid(cryptoAssetProperties.getOid());
            cycloneComponent.setCryptoProperties(cryptoProperties);
        }

        if (component.getOccurrences() != null && !component.getOccurrences().isEmpty()) {
            org.cyclonedx.model.Evidence evidence = new org.cyclonedx.model.Evidence();
            List<org.cyclonedx.model.component.evidence.Occurrence> occs = new ArrayList<>();
            for (Occurrence o: component.getOccurrences()) {
                occs.add(convertOccurrence(o));
            }
            evidence.setOccurrences(occs);
            cycloneComponent.setEvidence(evidence);
        }

        if (component.getExternalReferences() != null && !component.getExternalReferences().isEmpty()) {
            List<org.cyclonedx.model.ExternalReference> references = new ArrayList<>();
            for (ExternalReference ref : component.getExternalReferences()) {
                org.cyclonedx.model.ExternalReference cdxRef = new org.cyclonedx.model.ExternalReference();
                cdxRef.setType(ref.getType());
                cdxRef.setUrl(ref.getUrl());
                cdxRef.setComment(ref.getComment());
                references.add(cdxRef);
            }
            cycloneComponent.setExternalReferences(references);
        } else {
            cycloneComponent.setExternalReferences(null);
        }

        /*
        TODO: Assemble child/parent hierarchy. Components come in as flat, resolved dependencies.
         */
        /*
        if (component.getChildren() != null && component.getChildren().size() > 0) {
            final List<org.cyclonedx.model.Component> components = new ArrayList<>();
            final Component[] children = component.getChildren().toArray(new Component[0]);
            for (Component child : children) {
                components.add(convert(qm, child));
            }
            if (children.length > 0) {
                cycloneComponent.setComponents(components);
            }
        }
        */

        return cycloneComponent;
    }

    private static org.cyclonedx.model.component.evidence.Occurrence convertOccurrence(Occurrence o) {
        org.cyclonedx.model.component.evidence.Occurrence occ = new org.cyclonedx.model.component.evidence.Occurrence();
        occ.setBomRef(o.getBomRef());
        occ.setLine(o.getLine());
        occ.setLocation(o.getLocation());
        occ.setOffset(o.getOffset());
        occ.setSymbol(o.getSymbol());
        occ.setAdditionalContext(o.getAdditionalContext());
        return occ;
    }
    
    private static AlgorithmProperties convert(CryptoAlgorithmProperties algorithmProperties) {
        AlgorithmProperties ap = new AlgorithmProperties();
        ap.setPrimitive(algorithmProperties.getPrimitive());
        ap.setParameterSetIdentifier(algorithmProperties.getParameterSetIdentifier());
        ap.setCurve(algorithmProperties.getCurve());
        ap.setExecutionEnvironment(algorithmProperties.getExecutionEnvironment());
        ap.setImplementationPlatform(algorithmProperties.getImplementationPlatform());
        ap.setCertificationLevel(algorithmProperties.getCertificationLevel());
        ap.setMode(algorithmProperties.getMode());
        ap.setPadding(algorithmProperties.getPadding());
        ap.setCryptoFunctions(algorithmProperties.getCryptoFunctions());
        ap.setClassicalSecurityLevel(algorithmProperties.getClassicalSecurityLevel());
        ap.setNistQuantumSecurityLevel(algorithmProperties.getNistQuantumSecurityLevel());
        return ap;
    }

    private static CertificateProperties convert(CryptoCertificateProperties certificateProperties) {
        CertificateProperties cp = new CertificateProperties();
        cp.setSubjectName(certificateProperties.getSubjectName());
        cp.setIssuerName(certificateProperties.getIssuerName());
        cp.setNotValidBefore(DateUtil.toISO8601(certificateProperties.getNotValidBefore()));
        cp.setNotValidAfter(DateUtil.toISO8601(certificateProperties.getNotValidAfter()));
        cp.setSignatureAlgorithmRef(certificateProperties.getSignatureAlgorithmRef());
        cp.setSubjectPublicKeyRef(certificateProperties.getSubjectPublicKeyRef());
        cp.setCertificateFormat(certificateProperties.getCertificateFormat());
        cp.setCertificateExtension(certificateProperties.getCertificateExtension());
        return cp;
    }

    private static RelatedCryptoMaterialProperties convert(CryptoRelatedMaterialProperties cryptoMaterialProperties) {
        RelatedCryptoMaterialProperties rcmp = new RelatedCryptoMaterialProperties();
        rcmp.setType(cryptoMaterialProperties.getType());
        rcmp.setId(cryptoMaterialProperties.getIdentifier());
        rcmp.setState(cryptoMaterialProperties.getState());
        rcmp.setAlgorithmRef(cryptoMaterialProperties.getAlgorithmRef());
        rcmp.setCreationDate(DateUtil.toISO8601(cryptoMaterialProperties.getCreationDate()));
        rcmp.setActivationDate(DateUtil.toISO8601(cryptoMaterialProperties.getActivationDate()));
        rcmp.setUpdateDate(DateUtil.toISO8601(cryptoMaterialProperties.getUpdateDate()));
        rcmp.setExpirationDate(DateUtil.toISO8601(cryptoMaterialProperties.getExpirationDate()));
        rcmp.setValue(cryptoMaterialProperties.getValue());
        rcmp.setSize(cryptoMaterialProperties.getSize());
        rcmp.setFormat(cryptoMaterialProperties.getFormat());
        if (cryptoMaterialProperties.getSecuredByMechanism() != null || cryptoMaterialProperties.getSecuredByAlgorithmRef() != null) {
            SecuredBy sb = new SecuredBy();
            sb.setMechanism(cryptoMaterialProperties.getSecuredByMechanism().getName());
            sb.setAlgorithmRef(cryptoMaterialProperties.getAlgorithmRef());
            rcmp.setSecuredBy(sb);
        }
        return rcmp;
    }

    private static ProtocolProperties convert(CryptoProtocolProperties protocolProperties) {
        ProtocolProperties pp = new ProtocolProperties();
        pp.setType(protocolProperties.getType());
        pp.setVersion(protocolProperties.getVersion());

        if (protocolProperties.getCipherSuites() != null && !protocolProperties.getCipherSuites().isEmpty()) {
            final var suites = new ArrayList<org.cyclonedx.model.component.crypto.CipherSuite>();
            for (final CipherSuite cipherSuite : protocolProperties.getCipherSuites()) {
                suites.add(convertCipherSuite(cipherSuite));
            }
            pp.setCipherSuites(suites);
        }

        if (protocolProperties.getIkev2Types() != null) {
            Map<String, CryptoRef> cxIkev2Types = new HashMap<>();
            for( Ikev2Type it: protocolProperties.getIkev2Types()) {
                CryptoRef cr = new CryptoRef();
                cr.setRef(it.getRefs());
                cxIkev2Types.put(it.getType(), cr);
            }
            pp.setIkev2TransformTypes(cxIkev2Types);
        }

        // TODO: Enable when bug in cyclonedx xsd is fixed
        // if (protocolProperties.getCryptoRefs() != null) {
        //     CryptoRef cr = new CryptoRef();
        //     List<String> crs = new ArrayList<>();
        //     protocolProperties.getCryptoRefs().forEach(crs::add);
        //     cr.setRef(crs);
        //     pp.setCryptoRefArray(cr);
        // }

        return pp;
    }

    private static org.cyclonedx.model.component.crypto.CipherSuite convertCipherSuite(CipherSuite cs) {
        org.cyclonedx.model.component.crypto.CipherSuite ccs = new org.cyclonedx.model.component.crypto.CipherSuite();
        ccs.setName(cs.getName());
        ccs.setAlgorithms(cs.getAlgorithms());
        ccs.setIdentifiers(cs.getIdentifiers());
        return ccs;
    }
}
