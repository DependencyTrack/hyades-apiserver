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
package org.dependencytrack.workflow;

import alpine.Config;
import alpine.common.metrics.Metrics;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import io.github.nscuro.versatile.version.ext.ComponentVersion;
import io.micrometer.core.instrument.DistributionSummary;
import io.micrometer.core.instrument.Timer;
import org.apache.commons.collections4.ListUtils;
import org.cyclonedx.proto.v1_6.Source;
import org.cyclonedx.proto.v1_6.Vulnerability;
import org.dependencytrack.plugin.PluginManager;
import org.dependencytrack.proto.storage.v1alpha1.FileMetadata;
import org.dependencytrack.proto.workflow.payload.v1alpha1.AnalyzeProjectArgs;
import org.dependencytrack.proto.workflow.payload.v1alpha1.AnalyzeProjectVulnsResult;
import org.dependencytrack.proto.workflow.payload.v1alpha1.AnalyzeProjectVulnsResultX;
import org.dependencytrack.storage.FileStorage;
import org.dependencytrack.workflow.framework.ActivityRunContext;
import org.dependencytrack.workflow.framework.ActivityRunner;
import org.dependencytrack.workflow.framework.annotation.Activity;
import org.jdbi.v3.core.mapper.reflect.ConstructorMapper;
import org.jdbi.v3.core.statement.Query;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import us.springett.parsers.cpe.Cpe;
import us.springett.parsers.cpe.CpeParser;
import us.springett.parsers.cpe.exceptions.CpeParsingException;
import us.springett.parsers.cpe.util.Relation;
import us.springett.parsers.cpe.values.Part;

import jakarta.annotation.Nullable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

@Activity(name = "internal-analysis")
public class InternalAnalysisActivity implements ActivityRunner<AnalyzeProjectArgs, AnalyzeProjectVulnsResultX> {

    private static final Logger LOGGER = LoggerFactory.getLogger(InternalAnalysisActivity.class);

    private Timer componentQueryLatencyTimer;
    private Timer criteriaQueryLatencyTimer;
    private DistributionSummary componentCountDistribution;
    private DistributionSummary criteriaCountDistribution;

    public InternalAnalysisActivity() {
        if (Config.getInstance().getPropertyAsBoolean(Config.AlpineKey.METRICS_ENABLED)) {
            componentQueryLatencyTimer = Timer
                    .builder("dtrack.internal.analyzer.component.query.latency")
                    .register(Metrics.getRegistry());
            criteriaQueryLatencyTimer = Timer
                    .builder("dtrack.internal.analyzer.criteria.query.latency")
                    .register(Metrics.getRegistry());
            componentCountDistribution = DistributionSummary
                    .builder("dtrack.internal.analyzer.components")
                    .register(Metrics.getRegistry());
            criteriaCountDistribution = DistributionSummary
                    .builder("dtrack.internal.analyzer.criteria")
                    .register(Metrics.getRegistry());
        }
    }

    @Override
    public Optional<AnalyzeProjectVulnsResultX> run(final ActivityRunContext<AnalyzeProjectArgs> ctx) throws Exception {
        final AnalyzeProjectArgs args = ctx.argument().orElseThrow();

        final List<ScannableComponent> components;
        final Timer.Sample componentQueryLatencySample = Timer.start();
        try {
            components = fetchComponents(UUID.fromString(args.getProject().getUuid()));
        } finally {
            if (componentQueryLatencyTimer != null) {
                componentQueryLatencySample.stop(componentQueryLatencyTimer);
            }
        }
        if (components.isEmpty()) {
            return Optional.empty();
        }

        final var vulnsByComponentId = new HashMap<Long, Set<Vulnerability>>(components.size());
        final List<List<ScannableComponent>> componentBatches = ListUtils.partition(components, 100);
        for (final List<ScannableComponent> batch : componentBatches) {
            final Map<Long, Set<Vulnerability>> batchResult = analyzeComponents(batch);
            vulnsByComponentId.putAll(batchResult);
        }

        final var resultBuilder = AnalyzeProjectVulnsResult.newBuilder();
        for (final Map.Entry<Long, Set<Vulnerability>> entry : vulnsByComponentId.entrySet()) {
            resultBuilder.addResults(
                    AnalyzeProjectVulnsResult.ComponentResult.newBuilder()
                            .setComponentId(entry.getKey())
                            .addAllVulns(entry.getValue())
                            .build());
        }

        final FileMetadata resultFileMetadata;
        try (final var fileStorage = PluginManager.getInstance().getExtension(FileStorage.class)) {
            resultFileMetadata = fileStorage.store(
                    "internal-result", resultBuilder.build().toByteArray());
        }

        return Optional.of(AnalyzeProjectVulnsResultX.newBuilder()
                .setResultsFileMetadata(resultFileMetadata)
                .build());
    }

    private Map<Long, Set<Vulnerability>> analyzeComponents(final List<ScannableComponent> components) {
        LOGGER.info("Analyzing batch of {} components", components.size());

        final var componentIdsByCpe = new HashMap<String, List<Long>>();
        final var componentIdsByPurl = new HashMap<String, List<Long>>();

        for (final ScannableComponent component : components) {
            if (component.cpe() != null) {
                componentIdsByCpe.computeIfAbsent(component.cpe(),
                        ignored -> new ArrayList<>()).add(component.id());
            }
            if (component.purl() != null) {
                componentIdsByPurl.computeIfAbsent(component.purl(),
                        ignored -> new ArrayList<>()).add(component.id());
            }
        }

        int queryConditionIndex = 0;
        final var conditions = new ArrayList<QueryFilterCondition>();
        final var cpeByConditionIndex = new HashMap<Integer, String>(componentIdsByCpe.size());
        final var purlByConditionIndex = new HashMap<Integer, String>(componentIdsByPurl.size());

        for (final String cpe : componentIdsByCpe.keySet()) {
            final QueryFilterCondition condition = buildFilterConditionForCpe(cpe, queryConditionIndex++);
            if (condition != null) {
                cpeByConditionIndex.put(condition.index(), cpe);
                conditions.add(condition);
            }
        }

        for (final String purl : componentIdsByPurl.keySet()) {
            final QueryFilterCondition condition = buildFilterConditionForPurl(purl, queryConditionIndex++);
            if (condition != null) {
                purlByConditionIndex.put(condition.index(), purl);
                conditions.add(condition);
            }
        }

        final Map<Integer, List<MatchingCriteria>> criteriaByConditionIndex;
        final Timer.Sample criteriaQueryLatencySample = Timer.start();
        try {
            criteriaByConditionIndex = fetchMatchingCriteria(conditions);
        } finally {
            if (criteriaQueryLatencyTimer != null) {
                criteriaQueryLatencySample.stop(criteriaQueryLatencyTimer);
            }
        }

        if (criteriaByConditionIndex == null || criteriaByConditionIndex.isEmpty()) {
            return components.stream()
                    .collect(Collectors.toMap(
                            ScannableComponent::id,
                            ignored -> Collections.emptySet()));
        }

        final var matchedCriteriaIdByConditionIndex = new HashMap<Integer, Set<Long>>();
        for (final Map.Entry<Integer, List<MatchingCriteria>> entry : criteriaByConditionIndex.entrySet()) {
            final int conditionIndex = entry.getKey();
            final List<MatchingCriteria> criteriaList = entry.getValue();

            final String cpe = cpeByConditionIndex.get(conditionIndex);
            if (cpe != null) {
                final Set<Long> matchedCriteriaIds = evaluateCriteriaForCpe(cpe, criteriaList);
                matchedCriteriaIdByConditionIndex.put(conditionIndex, matchedCriteriaIds);
                continue;
            }

            final String purl = purlByConditionIndex.get(conditionIndex);
            if (purl != null) {
                final Set<Long> matchedCriteriaIds = evaluateCriteriaForPurl(purl, criteriaList);
                matchedCriteriaIdByConditionIndex.put(conditionIndex, matchedCriteriaIds);
            }
        }

        if (matchedCriteriaIdByConditionIndex.isEmpty()) {
            return components.stream()
                    .collect(Collectors.toMap(
                            ScannableComponent::id,
                            ignored -> Collections.emptySet()));
        }

        final Set<Long> uniqueMatchedCriteriaIds = matchedCriteriaIdByConditionIndex.values().stream()
                .flatMap(Collection::stream)
                .collect(Collectors.toSet());
        final Map<Long, List<VulnIdAndSource>> vulnsByCriteriaId = fetchVulnerabilitiesByCriteriaIds(uniqueMatchedCriteriaIds);

        final Map<Long, Set<Vulnerability>> vulnsByComponentId = new HashMap<>();
        for (final Map.Entry<Integer, Set<Long>> entry : matchedCriteriaIdByConditionIndex.entrySet()) {
            final int conditionIndex = entry.getKey();
            final List<Vulnerability> matchedVulns = entry.getValue().stream()
                    .flatMap(criteriaId -> vulnsByCriteriaId.getOrDefault(criteriaId, Collections.emptyList()).stream())
                    .map(vulnIdAndSource -> Vulnerability.newBuilder()
                            .setId(vulnIdAndSource.vulnId())
                            .setSource(Source.newBuilder().setName(vulnIdAndSource.source()).build())
                            .build())
                    .toList();

            final String cpe = cpeByConditionIndex.get(conditionIndex);
            if (cpe != null) {
                final List<Long> componentIds = componentIdsByCpe.get(cpe);
                if (componentIds == null) {
                    continue;
                }

                for (final Long componentId : componentIds) {
                    vulnsByComponentId.computeIfAbsent(
                            componentId, ignored -> new HashSet<>()).addAll(matchedVulns);
                }
            }

            final String purl = purlByConditionIndex.get(conditionIndex);
            if (purl != null) {
                final List<Long> componentIds = componentIdsByPurl.get(purl);
                if (componentIds == null) {
                    continue;
                }

                for (final Long componentId : componentIds) {
                    vulnsByComponentId.computeIfAbsent(
                            componentId, ignored -> new HashSet<>()).addAll(matchedVulns);
                }
            }
        }

        return vulnsByComponentId;
    }

    public record ScannableComponent(
            long id,
            String cpe,
            String purl) {
    }

    private List<ScannableComponent> fetchComponents(final UUID projectUuid) {
        final List<ScannableComponent> components = withJdbiHandle(handle -> {
            final Query query = handle.createQuery("""
                    SELECT "COMPONENT"."ID"
                         , "COMPONENT"."CPE"
                         , "COMPONENT"."PURL"
                      FROM "COMPONENT"
                     INNER JOIN "PROJECT"
                        ON "PROJECT"."ID" = "COMPONENT"."PROJECT_ID"
                     WHERE "PROJECT"."UUID" = :projectUuid
                       AND ("COMPONENT"."CPE" IS NOT NULL OR "COMPONENT"."PURL" IS NOT NULL)
                    """);

            return query
                    .bind("projectUuid", projectUuid)
                    .map(ConstructorMapper.of(ScannableComponent.class))
                    .list();
        });

        if (componentCountDistribution != null) {
            componentCountDistribution.record(components.size());
        }

        return components;
    }

    private record QueryFilterCondition(int index, String conditionStr, Map<String, Object> params) {
    }

    private QueryFilterCondition buildFilterConditionForCpe(final String cpeStr, final int conditionIndex) {
        final Cpe cpe;
        try {
            cpe = CpeParser.parse(cpeStr);
        } catch (CpeParsingException e) {
            LOGGER.warn("Failed to parse CPE: {}", cpeStr, e);
            return null;
        }

        final var params = new HashMap<String, Object>();
        final var filterParts = new ArrayList<String>();

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

        if (cpe.getPart() != Part.ANY && cpe.getPart() != Part.NA) {
            // | No. | Source A-V      | Target A-V | Relation             |
            // | :-- | :-------------- | :--------- | :------------------- |
            // | 3   | ANY             | i          | SUPERSET             |
            // | 7   | NA              | i          | DISJOINT             |
            // | 9   | i               | i          | EQUAL                |
            // | 10  | i               | k          | DISJOINT             |
            // | 14  | m1 + wild cards | m2         | SUPERSET or DISJOINT |
            filterParts.add("(\"PART\" = '*' OR \"PART\" = :cpePart%d)".formatted(conditionIndex));
            params.put("cpePart" + conditionIndex, cpe.getPart().getAbbreviation());

            // NOTE: Target *could* include wildcard, but the relation
            // for those cases is undefined:
            //
            // | No. | Source A-V      | Target A-V      | Relation   |
            // | :-- | :-------------- | :-------------- | :--------- |
            // | 4   | ANY             | m + wild cards  | undefined  |
            // | 8   | NA              | m + wild cards  | undefined  |
            // | 11  | i               | m + wild cards  | undefined  |
            // | 17  | m1 + wild cards | m2 + wild cards | undefined  |
        } else if (cpe.getPart() == Part.NA) {
            // | No. | Source A-V     | Target A-V | Relation |
            // | :-- | :------------- | :--------- | :------- |
            // | 2   | ANY            | NA         | SUPERSET |
            // | 6   | NA             | NA         | EQUAL    |
            // | 12  | i              | NA         | DISJOINT |
            // | 16  | m + wild cards | NA         | DISJOINT |
            filterParts.add("(\"PART\" = '*' OR \"PART\" = '-')");
        } else {
            // | No. | Source A-V     | Target A-V | Relation |
            // | :-- | :------------- | :--------- | :------- |
            // | 1   | ANY            | ANY        | EQUAL    |
            // | 5   | NA             | ANY        | SUBSET   |
            // | 13  | i              | ANY        | SUBSET   |
            // | 15  | m + wild cards | ANY        | SUBSET   |
            filterParts.add("\"PART\" IS NOT NULL");
        }

        if (!"*".equals(cpe.getVendor()) && !"-".equals(cpe.getVendor())) {
            filterParts.add("(\"VENDOR\" = '*' OR \"VENDOR\" = :cpeVendor%d)".formatted(conditionIndex));
            params.put("cpeVendor" + conditionIndex, cpe.getVendor());
        } else if ("-".equals(cpe.getVendor())) {
            filterParts.add("(\"VENDOR\" = '*' OR \"VENDOR\" = '-')");
        } else {
            filterParts.add("\"VENDOR\" IS NOT NULL");
        }

        if (!"*".equals(cpe.getProduct()) && !"-".equals(cpe.getProduct())) {
            filterParts.add("(\"PRODUCT\" = '*' OR \"PRODUCT\" = :cpeProduct%d)".formatted(conditionIndex));
            params.put("product" + conditionIndex, cpe.getProduct());
        } else if ("-".equals(cpe.getProduct())) {
            filterParts.add("(\"PRODUCT\" = '*' OR \"PRODUCT\" = '-')");
        } else {
            filterParts.add("\"PRODUCT\" IS NOT NULL");
        }

        return new QueryFilterCondition(
                conditionIndex,
                String.join(" AND ", filterParts),
                params);
    }

    private QueryFilterCondition buildFilterConditionForPurl(final String purlStr, final int conditionIndex) {
        final PackageURL purl;
        try {
            purl = new PackageURL(purlStr);
        } catch (MalformedPackageURLException e) {
            LOGGER.warn("Failed to parse purl: {}", purlStr, e);
            return null;
        }

        final var params = new HashMap<String, Object>();
        final var filterParts = new ArrayList<String>();

        if (purl.getType() != null) {
            filterParts.add("\"PURL_TYPE\" = :purlType" + conditionIndex);
            params.put("purlType" + conditionIndex, purl.getType());
        } else {
            filterParts.add("\"PURL_TYPE\" IS NULL");
        }

        if (purl.getNamespace() != null) {
            filterParts.add("\"PURL_NAMESPACE\" = :purlNamespace" + conditionIndex);
            params.put("purlNamespace" + conditionIndex, purl.getNamespace());
        } else {
            filterParts.add("\"PURL_NAMESPACE\" IS NULL");
        }

        if (purl.getName() != null) {
            filterParts.add("\"PURL_NAME\" = :purlName" + conditionIndex);
            params.put("purlName" + conditionIndex, purl.getName());
        } else {
            filterParts.add("\"PURL_NAME\" IS NULL");
        }

        return new QueryFilterCondition(
                conditionIndex,
                String.join(" AND ", filterParts),
                params);
    }

    public record MatchingCriteria(
            int conditionIndex,
            long id,
            @Nullable String cpe23,
            @Nullable String version,
            @Nullable String versionEndExcluding,
            @Nullable String versionEndIncluding,
            @Nullable String versionStartExcluding,
            @Nullable String versionStartIncluding) {
    }

    private Map<Integer, List<MatchingCriteria>> fetchMatchingCriteria(
            final List<QueryFilterCondition> conditions) {
        final var subQueries = new ArrayList<String>(conditions.size());
        final var params = new HashMap<String, Object>();

        for (final QueryFilterCondition condition : conditions) {
            subQueries.add("""
                    SELECT %d AS "CONDITION_INDEX"
                         , "ID"
                         , "CPE23"
                         , "VERSION"
                         , "VERSIONENDEXCLUDING"
                         , "VERSIONENDINCLUDING"
                         , "VERSIONSTARTEXCLUDING"
                         , "VERSIONSTARTINCLUDING"
                      FROM "VULNERABLESOFTWARE"
                     WHERE %s""".formatted(
                    condition.index(), condition.conditionStr()));
            params.putAll(condition.params());
        }

        final String queryStr = String.join(" UNION ALL ", subQueries);

        final List<MatchingCriteria> criteriaList = withJdbiHandle(
                handle -> handle.createQuery(queryStr)
                        .bindMap(params)
                        .map(ConstructorMapper.of(MatchingCriteria.class))
                        .list());

        if (criteriaCountDistribution != null) {
            criteriaCountDistribution.record(criteriaList.size());
        }

        return criteriaList.stream()
                .collect(Collectors.groupingBy(
                        MatchingCriteria::conditionIndex,
                        Collectors.toList()));
    }

    private Set<Long> evaluateCriteriaForCpe(
            final String cpeStr,
            final List<MatchingCriteria> criteriaList) {
        final Cpe targetCpe;
        try {
            targetCpe = CpeParser.parse(cpeStr);
        } catch (CpeParsingException e) {
            LOGGER.warn("Failed to parse target CPE: {}", cpeStr, e);
            return Collections.emptySet();
        }

        LOGGER.info("Evaluating {} vulnerability criteria against CPE {}", criteriaList.size(), cpeStr);
        return criteriaList.stream()
                .filter(criteria -> matchesCpe(criteria, targetCpe))
                .filter(criteria -> compareVersions(criteria, targetCpe.getVersion()))
                .map(MatchingCriteria::id)
                .collect(Collectors.toSet());
    }

    private Set<Long> evaluateCriteriaForPurl(
            final String purlStr,
            final List<MatchingCriteria> criteriaList) {
        final PackageURL purl;
        try {
            purl = new PackageURL(purlStr);
        } catch (MalformedPackageURLException e) {
            LOGGER.warn("Failed to parse purl: {}", purlStr, e);
            return Collections.emptySet();
        }

        return criteriaList.stream()
                .filter(criteria -> compareVersions(criteria, purl.getVersion()))
                .map(MatchingCriteria::id)
                .collect(Collectors.toSet());
    }

    public record VulnIdAndSource(long criteriaId, String vulnId, String source) {
    }

    private Map<Long, List<VulnIdAndSource>> fetchVulnerabilitiesByCriteriaIds(final Collection<Long> criteriaIds) {
        return withJdbiHandle(handle -> {
            final Query query = handle.createQuery("""
                    SELECT "VSV"."VULNERABLESOFTWARE_ID" AS "criteriaId"
                         , "V"."VULNID" AS "vulnId"
                         , "V"."SOURCE" AS "source"
                      FROM "VULNERABLESOFTWARE_VULNERABILITIES" AS "VSV"
                     INNER JOIN "VULNERABILITY" AS "V"
                        ON "V"."ID" = "VSV"."VULNERABILITY_ID"
                     WHERE "VSV"."VULNERABLESOFTWARE_ID" = ANY(:criteriaIds)
                    """);

            return query
                    .bindArray("criteriaIds", Long.class, criteriaIds)
                    .map(ConstructorMapper.of(VulnIdAndSource.class))
                    .stream()
                    .collect(Collectors.groupingBy(
                            VulnIdAndSource::criteriaId));
        });
    }

    private boolean matchesCpe(final MatchingCriteria criteria, final Cpe targetCpe) {
        if (targetCpe == null || criteria.cpe23() == null) {
            throw new IllegalArgumentException();
        }

        final Cpe criteriaCpe;
        try {
            criteriaCpe = CpeParser.parse(criteria.cpe23());
        } catch (CpeParsingException e) {
            LOGGER.warn("Failed to parse criteria CPE: {}", criteria.cpe23(), e);
            return false;
        }

        final List<Relation> relations = List.of(
                Cpe.compareAttribute(criteriaCpe.getPart().getAbbreviation(), targetCpe.getPart().getAbbreviation()),
                Cpe.compareAttribute(criteriaCpe.getVendor(), targetCpe.getVendor()),
                Cpe.compareAttribute(criteriaCpe.getProduct(), targetCpe.getProduct()),
                Cpe.compareAttribute(criteriaCpe.getVersion(), targetCpe.getVersion()),
                Cpe.compareAttribute(criteriaCpe.getUpdate(), targetCpe.getUpdate()),
                Cpe.compareAttribute(criteriaCpe.getEdition(), targetCpe.getEdition()),
                Cpe.compareAttribute(criteriaCpe.getLanguage(), targetCpe.getLanguage()),
                Cpe.compareAttribute(criteriaCpe.getSwEdition(), targetCpe.getSwEdition()),
                Cpe.compareAttribute(criteriaCpe.getTargetSw(), targetCpe.getTargetSw()),
                Cpe.compareAttribute(criteriaCpe.getTargetHw(), targetCpe.getTargetHw()),
                Cpe.compareAttribute(criteriaCpe.getOther(), targetCpe.getOther())
        );
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
            LOGGER.debug("{}: Dropped match with {} due to ambiguous vendor/product relation", targetCpe.toCpe23FS(), criteria.cpe23());
        }

        return isMatch;
    }

    static boolean compareVersions(final MatchingCriteria criteria, final String targetVersion) {
        //if any of the four conditions will be evaluated - then true;
        boolean result = (criteria.versionEndExcluding() != null && !criteria.versionEndExcluding().isEmpty())
                         || (criteria.versionStartExcluding() != null && !criteria.versionStartExcluding().isEmpty())
                         || (criteria.versionEndIncluding() != null && !criteria.versionEndIncluding().isEmpty())
                         || (criteria.versionStartIncluding() != null && !criteria.versionStartIncluding().isEmpty());

        // Modified from original by Steve Springett
        // Added null check: vs.getVersion() != null as purl sources that use version ranges may not have version populated.
        if (!result
            && criteria.version() != null
            && Cpe.compareAttribute(criteria.version(), targetVersion) != Relation.DISJOINT) {
            return true;
        }

        final ComponentVersion target = new ComponentVersion(targetVersion);
        if (target.getVersionParts() != null && target.getVersionParts().isEmpty()) {
            return false;
        }
        if (result
            && criteria.versionEndExcluding() != null
            && !criteria.versionEndExcluding().isEmpty()) {
            final ComponentVersion endExcluding = new ComponentVersion(criteria.versionEndExcluding());
            result = endExcluding.compareTo(target) > 0;
        }
        if (result
            && criteria.versionStartExcluding() != null
            && !criteria.versionStartExcluding().isEmpty()) {
            final ComponentVersion startExcluding = new ComponentVersion(criteria.versionStartExcluding());
            result = startExcluding.compareTo(target) < 0;
        }
        if (result
            && criteria.versionEndIncluding() != null
            && !criteria.versionEndIncluding().isEmpty()) {
            final ComponentVersion endIncluding = new ComponentVersion(criteria.versionEndIncluding());
            result &= endIncluding.compareTo(target) >= 0;
        }
        if (result
            && criteria.versionStartIncluding() != null
            && !criteria.versionStartIncluding().isEmpty()) {
            final ComponentVersion startIncluding = new ComponentVersion(criteria.versionStartIncluding());
            result &= startIncluding.compareTo(target) <= 0;
        }

        return result;
    }

}
