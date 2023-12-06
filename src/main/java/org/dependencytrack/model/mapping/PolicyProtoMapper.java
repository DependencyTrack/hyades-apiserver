package org.dependencytrack.model.mapping;

import com.google.protobuf.Timestamp;
import com.google.protobuf.util.Timestamps;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAlias;

import java.math.BigDecimal;
import java.util.Collections;
import java.util.Date;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.function.Supplier;
import java.util.stream.Stream;

import static org.dependencytrack.util.PersistenceUtil.assertNonPersistent;

public class PolicyProtoMapper {

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
        maybeSet(() -> vuln.getAliases() != null
                ? vuln.getAliases().stream().flatMap(PolicyProtoMapper::mapToProtos).distinct().toList()
                : Collections.emptyList(), protoBuilder::addAllAliases);
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

    private static Stream<org.dependencytrack.proto.policy.v1.Vulnerability.Alias> mapToProtos(final VulnerabilityAlias alias) {
        if (alias == null) {
            return Stream.empty();
        }

        // An object attached to a persistence context could do lazy loading of fields when accessing them.
        // Ensure this can't happen, as it could cause massive performance degradation.
        assertNonPersistent(alias, "alias must not be persistent");

        return alias.getAllBySource().entrySet().stream()
                .map(aliasEntry -> org.dependencytrack.proto.policy.v1.Vulnerability.Alias.newBuilder()
                        .setSource(aliasEntry.getKey().name())
                        .setId(aliasEntry.getValue())
                        .build());
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
