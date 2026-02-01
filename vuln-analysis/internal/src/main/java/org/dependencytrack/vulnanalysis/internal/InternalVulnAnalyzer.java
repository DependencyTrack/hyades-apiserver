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
package org.dependencytrack.vulnanalysis.internal;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import io.github.nscuro.versatile.Comparator;
import io.github.nscuro.versatile.Vers;
import io.github.nscuro.versatile.VersException;
import io.github.nscuro.versatile.spi.InvalidVersionException;
import io.github.nscuro.versatile.version.KnownVersioningSchemes;
import org.cyclonedx.proto.v1_6.Bom;
import org.cyclonedx.proto.v1_6.Component;
import org.cyclonedx.proto.v1_6.Property;
import org.cyclonedx.proto.v1_6.Source;
import org.cyclonedx.proto.v1_6.Vulnerability;
import org.cyclonedx.proto.v1_6.VulnerabilityAffects;
import org.dependencytrack.vulnanalysis.api.VulnAnalyzer;
import org.jdbi.v3.core.Jdbi;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import us.springett.parsers.cpe.Cpe;
import us.springett.parsers.cpe.CpeParser;
import us.springett.parsers.cpe.exceptions.CpeParsingException;
import us.springett.parsers.cpe.util.Relation;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.StringJoiner;
import java.util.stream.Collectors;

import static io.github.nscuro.versatile.version.KnownVersioningSchemes.SCHEME_GENERIC;

/**
 * @since 5.7.0
 */
final class InternalVulnAnalyzer implements VulnAnalyzer {

    private static final Logger LOGGER = LoggerFactory.getLogger(InternalVulnAnalyzer.class);
    private static final String INTERNAL_VULN_ID_PROPERTY = "dependencytrack:internal:vulnerability-id";

    private final Jdbi jdbi;

    InternalVulnAnalyzer(Jdbi jdbi) {
        this.jdbi = jdbi;
    }

    @Override
    public Bom analyze(Bom bom) {
        final var candidates = new ArrayList<CandidateComponent>();
        collectScannableComponents(bom.getComponentsList(), candidates);

        if (candidates.isEmpty()) {
            return Bom.getDefaultInstance();
        }

        // TODO: Check cache.

        final var candidatesByCoordinate = new HashMap<Coordinate, Set<CandidateComponent>>();

        for (final CandidateComponent candidate : candidates) {
            for (final Coordinate coordinate : Coordinate.of(candidate)) {
                candidatesByCoordinate.computeIfAbsent(coordinate, k -> new HashSet<>()).add(candidate);
            }
        }

        final var findingsByVuln = new HashMap<Long, Set<Long>>();
        final var vulnMetadata = new HashMap<Long, VulnMetadata>();

        final List<List<Coordinate>> coordinatePartitions = partition(List.copyOf(candidatesByCoordinate.keySet()));
        for (final var coordinatePartition : coordinatePartitions) {
            LOGGER.debug("Querying matching criteria for {} coordinates", coordinatePartition.size());
            final Map<Coordinate, List<MatchingCriteria>> criteriaListByCoordinate =
                    queryMatchingCriteria(coordinatePartition);

            for (final var entry : criteriaListByCoordinate.entrySet()) {
                final Coordinate coordinate = entry.getKey();
                final List<MatchingCriteria> criteriaList = entry.getValue();

                final Set<CandidateComponent> criteriaCandidates = candidatesByCoordinate.get(coordinate);
                if (criteriaCandidates == null || criteriaCandidates.isEmpty()) {
                    LOGGER.warn("No candidates found for {}", coordinate);
                    continue;
                }

                for (final MatchingCriteria criteria : criteriaList) {
                    for (final var candidate : criteriaCandidates) {
                        final var affectedComponentIds = findingsByVuln.get(criteria.vulnDbId());
                        if (affectedComponentIds != null && affectedComponentIds.contains(candidate.id())) {
                            // Already matched, no need to check another criteria.
                            continue;
                        }

                        if (isAffected(candidate, criteria)) {
                            findingsByVuln
                                    .computeIfAbsent(criteria.vulnDbId(), k -> new HashSet<>())
                                    .add(candidate.id());
                            vulnMetadata.putIfAbsent(
                                    criteria.vulnDbId(),
                                    new VulnMetadata(criteria.vulnId(), criteria.vulnSource()));
                        }
                    }
                }
            }
        }

        final var vulnerabilities = new ArrayList<Vulnerability>();
        for (final Map.Entry<Long, Set<Long>> entry : findingsByVuln.entrySet()) {
            final Long vulnDbId = entry.getKey();
            final Set<Long> affectedComponentIds = entry.getValue();
            final VulnMetadata metadata = vulnMetadata.get(vulnDbId);

            final var vulnBuilder = Vulnerability.newBuilder()
                    .setId(metadata.vulnId())
                    .setSource(Source.newBuilder().setName(metadata.source()))
                    .addProperties(Property.newBuilder()
                            .setName(INTERNAL_VULN_ID_PROPERTY)
                            .setValue(String.valueOf(vulnDbId)));

            for (final Long componentId : affectedComponentIds) {
                vulnBuilder
                        .addAffects(VulnerabilityAffects.newBuilder()
                                .setRef(String.valueOf(componentId)));
            }

            vulnerabilities.add(vulnBuilder.build());
        }

        return Bom.newBuilder()
                .addAllVulnerabilities(vulnerabilities)
                .build();
    }

    private Map<Coordinate, List<MatchingCriteria>> queryMatchingCriteria(List<Coordinate> coordinates) {
        final var queries = new ArrayList<String>();
        final var params = new HashMap<String, Object>();

        for (int i = 0; i < coordinates.size(); i++) {
            final Coordinate coordinate = coordinates.get(i);

            switch (coordinate) {
                case Coordinate.CpeCoordinate(String part, String vendor, String product) -> {
                    final var partParam = "cpePart" + i;
                    final var vendorParam = "cpeVendor" + i;
                    final var productParam = "cpeProduct" + i;

                    var queryBuilder = new StringJoiner(" ").add(/* language=SQL */ """
                            SELECT vs.*
                                 , v."ID" AS vuln_db_id
                                 , v."VULNID" AS vuln_id
                                 , v."SOURCE" AS vuln_source
                                 , %d AS coordinate_index
                              FROM "VULNERABLESOFTWARE" AS vs
                             INNER JOIN "VULNERABLESOFTWARE_VULNERABILITIES" AS vsv
                                ON vsv."VULNERABLESOFTWARE_ID" = vs."ID"
                             INNER JOIN "VULNERABILITY" AS v
                                ON v."ID" = vsv."VULNERABILITY_ID"
                             WHERE TRUE
                            """.formatted(i));

                    // The query composition below represents a partial implementation of the CPE
                    // matching logic. It makes references to table 6-2 of the CPE name matching
                    // specification: https://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir7696.pdf
                    //
                    // In CPE matching terms, the parameters of this method represent the target,
                    // and the `VulnerableSoftware`s in the database represent the source.
                    //
                    // While the source *can* contain wildcards ("*", "?"), there is currently (Oct. 2023)
                    // no occurrence of part, vendor, or product with wildcards in the NVD database.
                    // Evaluating wildcards in the source can only be done in-memory. If we wanted to do that,
                    // we'd have to fetch *all* records, which is not practical.

                    if (!"*".equals(part) && !"-".equals(part)) {
                        // | No. | Source A-V      | Target A-V | Relation             |
                        // | :-- | :-------------- | :--------- | :------------------- |
                        // | 3   | ANY             | i          | SUPERSET             |
                        // | 7   | NA              | i          | DISJOINT             |
                        // | 9   | i               | i          | EQUAL                |
                        // | 10  | i               | k          | DISJOINT             |
                        // | 14  | m1 + wild cards | m2         | SUPERSET or DISJOINT |
                        queryBuilder.add("AND \"PART\" IN ('*', :%s)".formatted(partParam));
                        params.put(partParam, part);

                        // NOTE: Target *could* include wildcard, but the relation
                        // for those cases is undefined:
                        //
                        // | No. | Source A-V      | Target A-V      | Relation   |
                        // | :-- | :-------------- | :-------------- | :--------- |
                        // | 4   | ANY             | m + wild cards  | undefined  |
                        // | 8   | NA              | m + wild cards  | undefined  |
                        // | 11  | i               | m + wild cards  | undefined  |
                        // | 17  | m1 + wild cards | m2 + wild cards | undefined  |
                    } else if ("-".equals(part)) {
                        // | No. | Source A-V     | Target A-V | Relation |
                        // | :-- | :------------- | :--------- | :------- |
                        // | 2   | ANY            | NA         | SUPERSET |
                        // | 6   | NA             | NA         | EQUAL    |
                        // | 12  | i              | NA         | DISJOINT |
                        // | 16  | m + wild cards | NA         | DISJOINT |
                        queryBuilder.add("AND \"PART\" IN ('*', '-')");
                    } else {
                        // | No. | Source A-V     | Target A-V | Relation |
                        // | :-- | :------------- | :--------- | :------- |
                        // | 1   | ANY            | ANY        | EQUAL    |
                        // | 5   | NA             | ANY        | SUBSET   |
                        // | 13  | i              | ANY        | SUBSET   |
                        // | 15  | m + wild cards | ANY        | SUBSET   |
                        queryBuilder.add("AND \"PART\" IS NOT NULL");
                    }

                    if (!"*".equals(vendor) && !"-".equals(vendor)) {
                        queryBuilder.add("AND \"VENDOR\" IN ('*', :%s)".formatted(vendorParam));
                        params.put(vendorParam, vendor);
                    } else if ("-".equals(vendor)) {
                        queryBuilder.add("AND \"VENDOR\" IN ('*', '-')");
                    } else {
                        queryBuilder.add("AND \"VENDOR\" IS NOT NULL");
                    }

                    if (!"*".equals(product) && !"-".equals(product)) {
                        queryBuilder.add("AND \"PRODUCT\" IN ('*', :%s)".formatted(productParam));
                        params.put(productParam, product);
                    } else if ("-".equals(product)) {
                        queryBuilder.add("AND \"PRODUCT\" IN ('*', '-')");
                    } else {
                        queryBuilder.add("AND \"PRODUCT\" IS NOT NULL");
                    }

                    queries.add(queryBuilder.toString());
                }
                case Coordinate.PurlCoordinate(String type, String namespace, String name) -> {
                    final var typeParam = "purlType" + i;
                    final var namespaceParam = "purlNamespace" + i;
                    final var nameParam = "purlName" + i;

                    var query = /* language=SQL */ """
                            SELECT vs.*
                                 , v."ID" AS vuln_db_id
                                 , v."VULNID" AS vuln_id
                                 , v."SOURCE" AS vuln_source
                                 , %d AS coordinate_index
                              FROM "VULNERABLESOFTWARE" AS vs
                             INNER JOIN "VULNERABLESOFTWARE_VULNERABILITIES" AS vsv
                                ON vsv."VULNERABLESOFTWARE_ID" = vs."ID"
                             INNER JOIN "VULNERABILITY" AS v
                                ON v."ID" = vsv."VULNERABILITY_ID"
                             WHERE "PURL_TYPE" = :%s
                               AND "PURL_NAME" = :%s
                            """.formatted(i, typeParam, nameParam);

                    params.put(typeParam, type);
                    params.put(nameParam, name);

                    if (namespace == null) {
                        query += "AND \"PURL_NAMESPACE\" IS NULL";
                    } else {
                        query += "AND \"PURL_NAMESPACE\" = :%s".formatted(namespaceParam);
                        params.put(namespaceParam, namespace);
                    }

                    queries.add(query);
                }
            }

            i++;
        }

        return jdbi.withHandle(handle -> handle
                .createQuery(String.join(" UNION ALL ", queries))
                .bindMap(params)
                .mapTo(MatchingCriteria.class)
                .collect(Collectors.groupingBy(
                        criteria -> coordinates.get(criteria.coordinateIndex()))));
    }

    private boolean isAffected(CandidateComponent component, MatchingCriteria criteria) {
        final String componentVersion;
        if (component.parsedPurl() != null && component.parsedPurl().getVersion() != null) {
            componentVersion = component.parsedPurl().getVersion();
        } else if (component.parsedCpe() != null && component.parsedCpe().getVersion() != null) {
            componentVersion = component.parsedCpe().getVersion();
        } else {
            LOGGER.warn("");
            return false;
        }

        if (criteria.cpe23() != null && component.parsedCpe() != null) {
            if (!matchesCpe(component.parsedCpe(), criteria)) {
                return false;
            }

            // Special cases for CPE matching of ANY (*) and NA (*) versions.
            // These don't make sense to use for version range comparison and
            // can be dealt with upfront based on the matching documentation:
            // https://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir7696.pdf
            if ("*".equals(componentVersion)) {
                // | No. | Source A-V     | Target A-V | Relation |
                // | :-- | :------------- | :--------- | :------- |
                // | 1   | ANY            | ANY        | EQUAL    |
                // | 5   | NA             | ANY        | SUBSET   |
                // | 13  | i              | ANY        | SUBSET   |
                // | 15  | m + wild cards | ANY        | SUBSET   |
                return true;
            } else if ("-".equals(componentVersion)) {
                // | No. | Source A-V     | Target A-V | Relation |
                // | :-- | :------------- | :--------- | :------- |
                // | 2   | ANY            | NA         | SUPERSET |
                // | 6   | NA             | NA         | EQUAL    |
                // | 12  | i              | NA         | DISJOINT |
                // | 16  | m + wild cards | NA         | DISJOINT |
                return "*".equals(criteria.version()) || "-".equals(criteria.version());
            }

            // Modified from original by Steve Springett
            // Added null check: vs.version() != null as purl sources that use version ranges may not have version populated.
            if (!criteria.hasRange()
                    && criteria.version() != null
                    && Cpe.compareAttribute(criteria.version(), componentVersion) != Relation.DISJOINT) {
                return true;
            }
        }

        final String versioningScheme = Optional
                .ofNullable(component.parsedPurl())
                .flatMap(KnownVersioningSchemes::fromPurl)
                .orElse(SCHEME_GENERIC);

        try {
            final var versBuilder = Vers.builder(versioningScheme);

            if (criteria.versionStartIncluding() != null && !criteria.versionStartIncluding().isEmpty()) {
                versBuilder.withConstraint(Comparator.GREATER_THAN_OR_EQUAL, criteria.versionStartIncluding());
            }
            if (criteria.versionStartExcluding() != null && !criteria.versionStartExcluding().isEmpty()) {
                versBuilder.withConstraint(Comparator.GREATER_THAN, criteria.versionStartExcluding());
            }
            if (criteria.versionEndExcluding() != null && !criteria.versionEndExcluding().isEmpty()) {
                versBuilder.withConstraint(Comparator.LESS_THAN, criteria.versionEndExcluding());
            }
            if (criteria.versionEndIncluding() != null && !criteria.versionEndIncluding().isEmpty()) {
                versBuilder.withConstraint(Comparator.LESS_THAN_OR_EQUAL, criteria.versionEndIncluding());
            }

            if (criteria.version() == null && !versBuilder.hasConstraints()) {
                versBuilder.withConstraint(Comparator.WILDCARD, null);
            } else if (criteria.version() != null
                    && !"*".equals(criteria.version())
                    && !"-".equals(criteria.version())) {
                versBuilder.withConstraint(Comparator.EQUAL, criteria.version());
            }

            final Vers vers = versBuilder.build().simplify();
            return vers.contains(componentVersion);
        } catch (VersException | InvalidVersionException e) {
            // Don't log the full stack trace here, it's too noisy.
            LOGGER.warn("Failed to compare versions: {}", e.getMessage());
            return false;
        }
    }

    private static boolean matchesCpe(Cpe targetCpe, MatchingCriteria criteria) {
        final List<Relation> relations = List.of(
                Cpe.compareAttribute(criteria.cpePart(), targetCpe.getPart().getAbbreviation().toLowerCase()),
                Cpe.compareAttribute(criteria.cpeVendor(), targetCpe.getVendor().toLowerCase()),
                Cpe.compareAttribute(criteria.cpeProduct(), targetCpe.getProduct().toLowerCase()),
                Cpe.compareAttribute(criteria.version(), targetCpe.getVersion()),
                Cpe.compareAttribute(criteria.cpeUpdate(), targetCpe.getUpdate()),
                Cpe.compareAttribute(criteria.cpeEdition(), targetCpe.getEdition()),
                Cpe.compareAttribute(criteria.cpeLanguage(), targetCpe.getLanguage()),
                Cpe.compareAttribute(criteria.cpeSwEdition(), targetCpe.getSwEdition()),
                Cpe.compareAttribute(criteria.cpeTargetSw(), targetCpe.getTargetSw()),
                Cpe.compareAttribute(criteria.cpeTargetHw(), targetCpe.getTargetHw()),
                Cpe.compareAttribute(criteria.cpeOther(), targetCpe.getOther()));
        if (relations.contains(Relation.DISJOINT)) {
            return false;
        }

        boolean isMatch = true;

        // Mixed SUBSET / SUPERSET relations in the vendor and product attribute are prone
        // to false positives: https://github.com/DependencyTrack/dependency-track/issues/3178
        final Relation vendorRelation = relations.get(1);
        final Relation productRelation = relations.get(2);
        isMatch &= !(vendorRelation == Relation.SUBSET && productRelation == Relation.SUPERSET);
        isMatch &= !(vendorRelation == Relation.SUPERSET && productRelation == Relation.SUBSET);

        if (!isMatch && LOGGER.isDebugEnabled()) {
            LOGGER.debug(
                    "{}: Dropped match with {} due to ambiguous vendor/product relation",
                    targetCpe.toCpe23FS(),
                    criteria.cpe23());
        }

        return isMatch;
    }

    private static void collectScannableComponents(List<Component> components, List<CandidateComponent> candidates) {
        for (final Component component : components) {
            if (!component.hasCpe() && !component.hasPurl()) {
                continue;
            }

            final long componentId;
            try {
                componentId = Long.parseLong(component.getBomRef());
            } catch (NumberFormatException e) {
                continue;
            }

            final Cpe parsedCpe = tryParseCpe(component);
            final PackageURL parsedPurl = tryParsePurl(component);

            if (parsedCpe == null && parsedPurl == null) {
                continue;
            }

            candidates.add(new CandidateComponent(componentId, parsedCpe, parsedPurl));

            if (component.getComponentsCount() > 0) {
                collectScannableComponents(component.getComponentsList(), candidates);
            }
        }
    }

    private static @Nullable Cpe tryParseCpe(Component component) {
        if (!component.hasCpe()) {
            return null;
        }

        try {
            return CpeParser.parse(component.getCpe());
        } catch (CpeParsingException e) {
            LOGGER.warn("Failed to parse CPE '{}'", component.getCpe(), e);
            return null;
        }
    }

    private static @Nullable PackageURL tryParsePurl(Component component) {
        if (!component.hasPurl()) {
            return null;
        }

        try {
            return new PackageURL(component.getPurl());
        } catch (MalformedPackageURLException e) {
            LOGGER.warn("Failed to parse PURL '{}'", component.getPurl(), e);
            return null;
        }
    }

    private record VulnMetadata(String vulnId, String source) {
    }

    private static <T> List<List<T>> partition(List<T> list) {
        final var partitions = new ArrayList<List<T>>();
        for (int i = 0; i < list.size(); i += 100) {
            partitions.add(list.subList(i, Math.min(i + 100, list.size())));
        }

        return partitions;
    }

}