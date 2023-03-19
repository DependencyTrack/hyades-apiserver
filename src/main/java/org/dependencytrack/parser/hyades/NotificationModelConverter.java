package org.dependencytrack.parser.hyades;

import alpine.notification.NotificationLevel;
import com.github.packageurl.PackageURL;
import com.google.protobuf.Any;
import com.google.protobuf.ByteString;
import com.google.protobuf.Timestamp;
import org.dependencytrack.model.Analysis;
import org.dependencytrack.model.Tag;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.notification.vo.AnalysisDecisionChange;
import org.dependencytrack.notification.vo.BomConsumedOrProcessed;
import org.dependencytrack.notification.vo.NewVulnerabilityIdentified;
import org.dependencytrack.notification.vo.NewVulnerableDependency;
import org.dependencytrack.notification.vo.VexConsumedOrProcessed;
import org.dependencytrack.notification.vo.ViolationAnalysisDecisionChange;
import org.dependencytrack.parser.common.resolver.CweResolver;
import org.dependencytrack.util.VulnerabilityUtil;
import org.hyades.proto.notification.v1.BomConsumedOrProcessedSubject;
import org.hyades.proto.notification.v1.Component;
import org.hyades.proto.notification.v1.Group;
import org.hyades.proto.notification.v1.Level;
import org.hyades.proto.notification.v1.NewVulnerabilitySubject;
import org.hyades.proto.notification.v1.NewVulnerableDependencySubject;
import org.hyades.proto.notification.v1.Notification;
import org.hyades.proto.notification.v1.Policy;
import org.hyades.proto.notification.v1.PolicyCondition;
import org.hyades.proto.notification.v1.PolicyViolation;
import org.hyades.proto.notification.v1.PolicyViolationAnalysisDecisionChangeSubject;
import org.hyades.proto.notification.v1.Project;
import org.hyades.proto.notification.v1.Scope;
import org.hyades.proto.notification.v1.VexConsumedOrProcessedSubject;
import org.hyades.proto.notification.v1.Vulnerability;
import org.hyades.proto.notification.v1.VulnerabilityAnalysis;
import org.hyades.proto.notification.v1.VulnerabilityAnalysisDecisionChangeSubject;
import org.hyades.proto.notification.v1.VulnerabilityAnalysisLevel;

import java.math.BigDecimal;
import java.time.ZoneOffset;
import java.util.Collections;
import java.util.Objects;
import java.util.Optional;

import static org.hyades.proto.notification.v1.Group.GROUP_ANALYZER;
import static org.hyades.proto.notification.v1.Group.GROUP_BOM_CONSUMED;
import static org.hyades.proto.notification.v1.Group.GROUP_BOM_PROCESSED;
import static org.hyades.proto.notification.v1.Group.GROUP_CONFIGURATION;
import static org.hyades.proto.notification.v1.Group.GROUP_DATASOURCE_MIRRORING;
import static org.hyades.proto.notification.v1.Group.GROUP_FILE_SYSTEM;
import static org.hyades.proto.notification.v1.Group.GROUP_INDEXING_SERVICE;
import static org.hyades.proto.notification.v1.Group.GROUP_INTEGRATION;
import static org.hyades.proto.notification.v1.Group.GROUP_NEW_VULNERABILITY;
import static org.hyades.proto.notification.v1.Group.GROUP_NEW_VULNERABLE_DEPENDENCY;
import static org.hyades.proto.notification.v1.Group.GROUP_POLICY_VIOLATION;
import static org.hyades.proto.notification.v1.Group.GROUP_PROJECT_AUDIT_CHANGE;
import static org.hyades.proto.notification.v1.Group.GROUP_PROJECT_CREATED;
import static org.hyades.proto.notification.v1.Group.GROUP_REPOSITORY;
import static org.hyades.proto.notification.v1.Group.GROUP_UNSPECIFIED;
import static org.hyades.proto.notification.v1.Group.GROUP_VEX_CONSUMED;
import static org.hyades.proto.notification.v1.Group.GROUP_VEX_PROCESSED;
import static org.hyades.proto.notification.v1.Level.LEVEL_ERROR;
import static org.hyades.proto.notification.v1.Level.LEVEL_INFORMATIONAL;
import static org.hyades.proto.notification.v1.Level.LEVEL_WARNING;
import static org.hyades.proto.notification.v1.Scope.SCOPE_PORTFOLIO;
import static org.hyades.proto.notification.v1.Scope.SCOPE_SYSTEM;
import static org.hyades.proto.notification.v1.Scope.SCOPE_UNSPECIFIED;
import static org.hyades.proto.notification.v1.VulnerabilityAnalysisLevel.VULNERABILITY_ANALYSIS_LEVEL_BOM_UPLOAD;
import static org.hyades.proto.notification.v1.VulnerabilityAnalysisLevel.VULNERABILITY_ANALYSIS_LEVEL_PERIODIC;
import static org.hyades.proto.notification.v1.VulnerabilityAnalysisLevel.VULNERABILITY_ANALYSIS_LEVEL_UNSPECIFIED;

public final class NotificationModelConverter {

    private NotificationModelConverter() {
    }

    public static Notification convert(final alpine.notification.Notification alpineNotification) {
        final Notification.Builder builder = Notification.newBuilder()
                .setLevel(convert(alpineNotification.getLevel()))
                .setScope(convertScope(alpineNotification.getScope()))
                .setGroup(convertGroup(alpineNotification.getGroup()))
                .setTimestamp(Timestamp.newBuilder()
                        .setSeconds(alpineNotification.getTimestamp().toEpochSecond(ZoneOffset.UTC)));

        Optional.ofNullable(alpineNotification.getTitle()).ifPresent(builder::setTitle);
        Optional.ofNullable(alpineNotification.getContent()).ifPresent(builder::setContent);
        Optional.ofNullable(alpineNotification.getSubject())
                .flatMap(NotificationModelConverter::convert)
                .ifPresent(builder::setSubject);

        return builder.build();
    }

    private static Level convert(final NotificationLevel level) {
        return switch (level) {
            case ERROR -> LEVEL_ERROR;
            case WARNING -> LEVEL_WARNING;
            case INFORMATIONAL -> LEVEL_INFORMATIONAL;
        };
    }

    private static Scope convertScope(final String scope) {
        final NotificationScope scopeEnum;
        try {
            scopeEnum = NotificationScope.valueOf(scope);
        } catch (IllegalArgumentException e) {
            return SCOPE_UNSPECIFIED;
        }

        return switch (scopeEnum) {
            case PORTFOLIO -> SCOPE_PORTFOLIO;
            case SYSTEM -> SCOPE_SYSTEM;
        };
    }

    private static Group convertGroup(final String group) {
        final NotificationGroup groupEnum;
        try {
            groupEnum = NotificationGroup.valueOf(group);
        } catch (IllegalArgumentException e) {
            return GROUP_UNSPECIFIED;
        }

        return switch (groupEnum) {
            case CONFIGURATION -> GROUP_CONFIGURATION;
            case DATASOURCE_MIRRORING -> GROUP_DATASOURCE_MIRRORING;
            case REPOSITORY -> GROUP_REPOSITORY;
            case INTEGRATION -> GROUP_INTEGRATION;
            case INDEXING_SERVICE -> GROUP_INDEXING_SERVICE;
            case FILE_SYSTEM -> GROUP_FILE_SYSTEM;
            case ANALYZER -> GROUP_ANALYZER;
            case NEW_VULNERABILITY -> GROUP_NEW_VULNERABILITY;
            case NEW_VULNERABLE_DEPENDENCY -> GROUP_NEW_VULNERABLE_DEPENDENCY;
            case PROJECT_AUDIT_CHANGE -> GROUP_PROJECT_AUDIT_CHANGE;
            case BOM_CONSUMED -> GROUP_BOM_CONSUMED;
            case BOM_PROCESSED -> GROUP_BOM_PROCESSED;
            case VEX_CONSUMED -> GROUP_VEX_CONSUMED;
            case VEX_PROCESSED -> GROUP_VEX_PROCESSED;
            case POLICY_VIOLATION -> GROUP_POLICY_VIOLATION;
            case PROJECT_CREATED -> GROUP_PROJECT_CREATED;
        };
    }

    private static Optional<com.google.protobuf.Any> convert(final Object subject) {
        if (subject instanceof final NewVulnerabilityIdentified nvi) {
            return Optional.of(Any.pack(convert(nvi)));
        } else if (subject instanceof final NewVulnerableDependency nvd) {
            return Optional.of(Any.pack(convert(nvd)));
        } else if (subject instanceof final AnalysisDecisionChange adc) {
            return Optional.of(Any.pack(convert(adc)));
        } else if (subject instanceof final ViolationAnalysisDecisionChange vadc) {
            return Optional.of(Any.pack(convert(vadc)));
        } else if (subject instanceof final BomConsumedOrProcessed bcop) {
            return Optional.of(Any.pack(convert(bcop)));
        } else if (subject instanceof final VexConsumedOrProcessed vcop) {
            return Optional.of(Any.pack(convert(vcop)));
        }

        return Optional.empty();
    }

    private static NewVulnerabilitySubject convert(final NewVulnerabilityIdentified subject) {
        final NewVulnerabilitySubject.Builder builder = NewVulnerabilitySubject.newBuilder()
                .setComponent(convert(subject.getComponent()))
                .setProject(convert(subject.getComponent().getProject()))
                .setVulnerability(convert(subject.getVulnerability()))
                .setAnalysisLevel(convert(subject.getVulnerabilityAnalysisLevel()));

        subject.getAffectedProjects().stream()
                .map(NotificationModelConverter::convert)
                .forEach(builder::addAffectedProjects);

        return builder.build();
    }

    private static NewVulnerableDependencySubject convert(final NewVulnerableDependency subject) {
        final NewVulnerableDependencySubject.Builder builder = NewVulnerableDependencySubject.newBuilder()
                .setComponent(convert(subject.getComponent()))
                .setProject(convert(subject.getComponent().getProject()));

        subject.getVulnerabilities().stream()
                .map(NotificationModelConverter::convert)
                .forEach(builder::addVulnerabilities);

        return builder.build();
    }

    private static VulnerabilityAnalysisDecisionChangeSubject convert(final AnalysisDecisionChange subject) {
        return VulnerabilityAnalysisDecisionChangeSubject.newBuilder()
                .setComponent(convert(subject.getComponent()))
                .setProject(convert(subject.getProject()))
                .setVulnerability(convert(subject.getVulnerability()))
                .setAnalysis(convert(subject.getAnalysis()))
                .build();
    }

    private static PolicyViolationAnalysisDecisionChangeSubject convert(final ViolationAnalysisDecisionChange subject) {
        return PolicyViolationAnalysisDecisionChangeSubject.newBuilder()
                .setComponent(convert(subject.getComponent()))
                .setProject(convert(subject.getComponent().getProject()))
                .setPolicyViolation(convert(subject.getPolicyViolation()))
                .build();
    }

    private static BomConsumedOrProcessedSubject convert(final BomConsumedOrProcessed subject) {
        return BomConsumedOrProcessedSubject.newBuilder()
                .setProject(convert(subject.getProject()))
                .setBom(ByteString.copyFromUtf8(subject.getBom()))
                .setFormat(subject.getFormat().getFormatShortName())
                .setSpecVersion(subject.getSpecVersion())
                .build();
    }

    private static VexConsumedOrProcessedSubject convert(final VexConsumedOrProcessed subject) {
        return VexConsumedOrProcessedSubject.newBuilder()
                .setProject(convert(subject.getProject()))
                .setVex(ByteString.copyFromUtf8(subject.getVex()))
                .setFormat(subject.getFormat().getFormatShortName())
                .setSpecVersion(subject.getSpecVersion())
                .build();
    }

    private static Component convert(final org.dependencytrack.model.Component component) {
        final Component.Builder builder = Component.newBuilder()
                .setUuid(component.getUuid().toString())
                .setName(component.getName());

        Optional.ofNullable(component.getGroup()).ifPresent(builder::setGroup);
        Optional.ofNullable(component.getVersion()).ifPresent(builder::setVersion);
        Optional.ofNullable(component.getPurl()).map(PackageURL::canonicalize).ifPresent(builder::setPurl);
        Optional.ofNullable(component.getMd5()).ifPresent(builder::setMd5);
        Optional.ofNullable(component.getSha1()).ifPresent(builder::setSha1);
        Optional.ofNullable(component.getSha256()).ifPresent(builder::setSha256);
        Optional.ofNullable(component.getSha512()).ifPresent(builder::setSha512);

        return builder.build();
    }

    private static Project convert(final org.dependencytrack.model.Project project) {
        final Project.Builder builder = Project.newBuilder()
                .setUuid(project.getUuid().toString())
                .setName(project.getName());

        Optional.ofNullable(project.getVersion()).ifPresent(builder::setVersion);
        Optional.ofNullable(project.getDescription()).ifPresent(builder::setDescription);
        Optional.ofNullable(project.getTags())
                .orElseGet(Collections::emptyList).stream()
                .map(Tag::getName)
                .forEach(builder::addTags);

        return builder.build();
    }

    private static Vulnerability convert(final org.dependencytrack.model.Vulnerability vulnerability) {
        final Vulnerability.Builder builder = Vulnerability.newBuilder()
                .setUuid(vulnerability.getUuid().toString())
                .setId(vulnerability.getVulnId())
                .setSource(vulnerability.getSource());

        if (vulnerability.getAliases() != null) {
            VulnerabilityUtil.getUniqueAliases(vulnerability).stream()
                    .map(entry -> Vulnerability.Alias.newBuilder()
                            .setId(entry.getValue())
                            .setSource(entry.getKey().name()))
                    .forEach(builder::addAliases);
        }
        Optional.ofNullable(vulnerability.getTitle()).ifPresent(builder::setTitle);
        Optional.ofNullable(vulnerability.getSubTitle()).ifPresent(builder::setSubTitle);
        Optional.ofNullable(vulnerability.getDescription()).ifPresent(builder::setDescription);
        Optional.ofNullable(vulnerability.getRecommendation()).ifPresent(builder::setRecommendation);
        Optional.ofNullable(vulnerability.getCvssV2BaseScore()).map(BigDecimal::doubleValue).ifPresent(builder::setCvssV2);
        Optional.ofNullable(vulnerability.getCvssV3BaseScore()).map(BigDecimal::doubleValue).ifPresent(builder::setCvssV3);
        Optional.ofNullable(vulnerability.getOwaspRRLikelihoodScore()).map(BigDecimal::doubleValue).ifPresent(builder::setOwaspRrLikelihood);
        Optional.ofNullable(vulnerability.getOwaspRRTechnicalImpactScore()).map(BigDecimal::doubleValue).ifPresent(builder::setOwaspRrTechnicalImpact);
        Optional.ofNullable(vulnerability.getOwaspRRBusinessImpactScore()).map(BigDecimal::doubleValue).ifPresent(builder::setOwaspRrBusinessImpact);
        Optional.ofNullable(vulnerability.getSeverity()).map(Enum::name).ifPresent(builder::setSeverity);
        Optional.ofNullable(vulnerability.getCwes())
                .orElseGet(Collections::emptyList).stream()
                .map(CweResolver.getInstance()::lookup)
                .filter(Objects::nonNull)
                .map(NotificationModelConverter::convert)
                .forEach(builder::addCwes);

        return builder.build();
    }

    private static PolicyViolation convert(final org.dependencytrack.model.PolicyViolation policyViolation) {
        return PolicyViolation.newBuilder()
                .setUuid(policyViolation.getUuid().toString())
                .setType(policyViolation.getType().name())
                .setTimestamp(Timestamp.newBuilder()
                        .setSeconds(policyViolation.getTimestamp().getTime() / 1000))
                .setCondition(convert(policyViolation.getPolicyCondition()))
                .build();
    }

    private static PolicyCondition convert(final org.dependencytrack.model.PolicyCondition policyCondition) {
        return PolicyCondition.newBuilder()
                .setUuid(policyCondition.getUuid().toString())
                .setSubject(policyCondition.getSubject().name())
                .setOperator(policyCondition.getOperator().name())
                .setValue(policyCondition.getValue())
                .setPolicy(convert(policyCondition.getPolicy()))
                .build();
    }

    private static Policy convert(final org.dependencytrack.model.Policy policy) {
        return Policy.newBuilder()
                .setUuid(policy.getUuid().toString())
                .setName(policy.getName())
                .setViolationState(policy.getViolationState().name())
                .build();
    }

    private static VulnerabilityAnalysis convert(final Analysis analysis) {
        final VulnerabilityAnalysis.Builder builder = VulnerabilityAnalysis.newBuilder()
                .setComponent(convert(analysis.getComponent()))
                .setProject(convert(analysis.getProject()))
                .setVulnerability(convert(analysis.getVulnerability()))
                .setSuppressed(analysis.isSuppressed());

        Optional.ofNullable(analysis.getAnalysisState()).map(Enum::name).ifPresent(builder::setState);

        return builder.build();
    }

    private static Vulnerability.Cwe convert(final org.dependencytrack.model.Cwe cwe) {
        return Vulnerability.Cwe.newBuilder()
                .setId(cwe.getCweId())
                .setName(cwe.getName())
                .build();
    }

    private static VulnerabilityAnalysisLevel convert(final org.dependencytrack.model.VulnerabilityAnalysisLevel level) {
        return switch (level) {
            case BOM_UPLOAD_ANALYSIS -> VULNERABILITY_ANALYSIS_LEVEL_BOM_UPLOAD;
            case PERIODIC_ANALYSIS -> VULNERABILITY_ANALYSIS_LEVEL_PERIODIC;
            default -> VULNERABILITY_ANALYSIS_LEVEL_UNSPECIFIED;
        };
    }

}
