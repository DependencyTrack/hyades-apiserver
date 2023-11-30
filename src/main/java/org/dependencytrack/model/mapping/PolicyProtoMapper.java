package org.dependencytrack.model.mapping;

import com.google.protobuf.Timestamp;
import com.google.protobuf.util.Timestamps;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Tag;
import org.dependencytrack.model.Vulnerability;

import java.math.BigDecimal;
import java.util.Collections;
import java.util.Date;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.function.Supplier;

import static org.dependencytrack.util.PersistenceUtil.assertNonPersistent;

/**
 * Utility class to map from persistence model ({@code org.dependencytrack.model}) to policy Protobuf
 * model ({@code org.dependencytrack.proto.policy.v1}).
 */
public final class PolicyProtoMapper {

    private PolicyProtoMapper() {
    }

    public static org.dependencytrack.proto.policy.v1.Component mapToProto(final Component component) {
        if (component == null) {
            return org.dependencytrack.proto.policy.v1.Component.getDefaultInstance();
        }

        // An object attached to a persistence context could do lazy loading of fields when accessing them.
        // Ensure this can't happen, as it could cause massive performance degradation.
        assertNonPersistent(component, "component must not be persistent");

        final org.dependencytrack.proto.policy.v1.Component.Builder protoBuilder =
                org.dependencytrack.proto.policy.v1.Component.newBuilder();
        maybeSet(asString(component.getUuid()), protoBuilder::setUuid);
        maybeSet(component::getGroup, protoBuilder::setGroup);
        maybeSet(component::getName, protoBuilder::setName);
        maybeSet(component::getVersion, protoBuilder::setVersion);
        maybeSet(asString(component.getClassifier()), protoBuilder::setClassifier);
        maybeSet(component::getCpe, protoBuilder::setCpe);
        maybeSet(() -> component.getPurl() != null ? component.getPurl().canonicalize() : null, protoBuilder::setPurl);
        maybeSet(component::getSwidTagId, protoBuilder::setSwidTagId);
        maybeSet(component::isInternal, protoBuilder::setIsInternal);
        maybeSet(component::getMd5, protoBuilder::setMd5);
        maybeSet(component::getSha1, protoBuilder::setSha1);
        maybeSet(component::getSha256, protoBuilder::setSha256);
        maybeSet(component::getSha384, protoBuilder::setSha384);
        maybeSet(component::getSha512, protoBuilder::setSha512);
        maybeSet(component::getSha3_256, protoBuilder::setSha3256);
        maybeSet(component::getSha3_384, protoBuilder::setSha3384);
        maybeSet(component::getSha3_512, protoBuilder::setSha3512);
        maybeSet(component::getBlake2b_256, protoBuilder::setBlake2B256);
        maybeSet(component::getBlake2b_384, protoBuilder::setBlake2B384);
        maybeSet(component::getBlake2b_512, protoBuilder::setBlake2B512);
        maybeSet(component::getBlake3, protoBuilder::setBlake3);
        maybeSet(component::getLicense, protoBuilder::setLicenseName);
        maybeSet(component::getLicenseExpression, protoBuilder::setLicenseExpression);
        // TODO: Resolved license
        maybeSet(() -> (component.getRepositoryMeta() != null && component.getRepositoryMeta().getLatestVersion() != null)
                ? component.getRepositoryMeta().getLatestVersion() : null, protoBuilder::setLatestVersion);

        return protoBuilder.build();
    }

    public static org.dependencytrack.proto.policy.v1.Project mapToProto(final Project project) {
        if (project == null) {
            return org.dependencytrack.proto.policy.v1.Project.getDefaultInstance();
        }

        // An object attached to a persistence context could do lazy loading of fields when accessing them.
        // Ensure this can't happen, as it could cause massive performance degradation.
        assertNonPersistent(project, "project must not be persistent");

        final org.dependencytrack.proto.policy.v1.Project.Builder protoBuilder =
                org.dependencytrack.proto.policy.v1.Project.newBuilder();
        maybeSet(asString(project.getUuid()), protoBuilder::setUuid);
        maybeSet(project::getGroup, protoBuilder::setGroup);
        maybeSet(project::getName, protoBuilder::setName);
        maybeSet(project::getVersion, protoBuilder::setVersion);
        maybeSet(asString(project.getClassifier()), protoBuilder::setClassifier);
        maybeSet(() -> project.isActive() != null ? project.isActive() : true, protoBuilder::setIsActive);
        maybeSet(() -> project.getTags() != null ? project.getTags().stream().map(Tag::getName).toList() : Collections.emptyList(), protoBuilder::addAllTags);
        // TODO: Properties
        maybeSet(project::getCpe, protoBuilder::setCpe);
        maybeSet(() -> project.getPurl() != null ? project.getPurl().canonicalize() : null, protoBuilder::setPurl);
        maybeSet(project::getSwidTagId, protoBuilder::setSwidTagId);
        maybeSet(asTimestamp(project.getLastBomImport()), protoBuilder::setLastBomImport);

        return protoBuilder.build();
    }

    public static org.dependencytrack.proto.policy.v1.Vulnerability mapToProto(final Vulnerability vuln) {
        if (vuln == null) {
            return org.dependencytrack.proto.policy.v1.Vulnerability.getDefaultInstance();
        }

        // An object attached to a persistence context could do lazy loading of fields when accessing them.
        // Ensure this can't happen, as it could cause massive performance degradation.
        assertNonPersistent(vuln, "vuln must not be persistent");

        final org.dependencytrack.proto.policy.v1.Vulnerability.Builder protoBuilder =
                org.dependencytrack.proto.policy.v1.Vulnerability.newBuilder();
        maybeSet(asString(vuln.getUuid()), protoBuilder::setUuid);
        maybeSet(vuln::getVulnId, protoBuilder::setId);
        maybeSet(vuln::getSource, protoBuilder::setSource);
        // TODO: Aliases
        maybeSet(vuln::getCwes, protoBuilder::addAllCwes);
        maybeSet(asTimestamp(vuln.getCreated()), protoBuilder::setCreated);
        maybeSet(asTimestamp(vuln.getPublished()), protoBuilder::setPublished);
        maybeSet(asTimestamp(vuln.getUpdated()), protoBuilder::setUpdated);
        maybeSet(asString(vuln.getSeverity()), protoBuilder::setSeverity);
        maybeSet(asDouble(vuln.getCvssV2BaseScore()), protoBuilder::setCvssv2BaseScore);
        maybeSet(asDouble(vuln.getCvssV2ImpactSubScore()), protoBuilder::setCvssv2ImpactSubscore);
        maybeSet(asDouble(vuln.getCvssV2ExploitabilitySubScore()), protoBuilder::setCvssv2ExploitabilitySubscore);
        maybeSet(vuln::getCvssV2Vector, protoBuilder::setCvssv2Vector);
        maybeSet(asDouble(vuln.getCvssV3BaseScore()), protoBuilder::setCvssv3BaseScore);
        maybeSet(asDouble(vuln.getCvssV3ImpactSubScore()), protoBuilder::setCvssv3ImpactSubscore);
        maybeSet(asDouble(vuln.getCvssV3ExploitabilitySubScore()), protoBuilder::setCvssv3ExploitabilitySubscore);
        maybeSet(vuln::getCvssV3Vector, protoBuilder::setCvssv3Vector);
        maybeSet(asDouble(vuln.getOwaspRRBusinessImpactScore()), protoBuilder::setOwaspRrBusinessImpactScore);
        maybeSet(asDouble(vuln.getOwaspRRLikelihoodScore()), protoBuilder::setOwaspRrLikelihoodScore);
        maybeSet(asDouble(vuln.getOwaspRRTechnicalImpactScore()), protoBuilder::setOwaspRrTechnicalImpactScore);
        maybeSet(vuln::getOwaspRRVector, protoBuilder::setOwaspRrVector);
        maybeSet(asDouble(vuln.getEpssScore()), protoBuilder::setEpssScore);
        maybeSet(asDouble(vuln.getEpssPercentile()), protoBuilder::setEpssPercentile);

        return protoBuilder.build();
    }

    private static <V> void maybeSet(final Supplier<V> getter, final Consumer<V> setter) {
        final V modelValue = getter.get();
        if (modelValue == null) {
            return;
        }

        setter.accept(modelValue);
    }

    private static Supplier<Double> asDouble(final BigDecimal bigDecimal) {
        return () -> bigDecimal != null ? bigDecimal.doubleValue() : null;
    }

    private static Supplier<String> asString(final Enum<?> enumInstance) {
        return () -> enumInstance != null ? enumInstance.name() : null;
    }

    private static Supplier<String> asString(final UUID uuid) {
        return () -> uuid != null ? uuid.toString() : null;
    }

    private static Supplier<Timestamp> asTimestamp(final Date date) {
        return () -> date != null ? Timestamps.fromDate(date) : null;
    }

}
