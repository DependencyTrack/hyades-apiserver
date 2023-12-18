package org.dependencytrack.persistence.jdbi.mapping;

import com.fasterxml.jackson.core.type.TypeReference;
import org.dependencytrack.model.Cwe;
import org.dependencytrack.model.Finding;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.VulnerabilityAlias;
import org.dependencytrack.parser.common.resolver.CweResolver;
import org.jdbi.v3.core.mapper.RowMapper;
import org.jdbi.v3.core.statement.StatementContext;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import static org.dependencytrack.persistence.jdbi.mapping.RowMapperUtil.deserializeJson;
import static org.dependencytrack.persistence.jdbi.mapping.RowMapperUtil.maybeSet;
import static org.dependencytrack.persistence.jdbi.mapping.RowMapperUtil.stringArray;

public class FindingRowMapper implements RowMapper<Finding> {

    private static final TypeReference<List<VulnerabilityAlias>> VULNERABILITY_ALIASES_TYPE_REF = new TypeReference<>() {
    };

    @Override
    public Finding map(final ResultSet rs, final StatementContext ctx) throws SQLException {
        final var analysis = new HashMap<String, Object>();
        final var attribution = new HashMap<String, Object>();
        final var component = new HashMap<String, Object>();
        final var vuln = new HashMap<String, Object>();

        maybeSet(rs, "projectUuid", ResultSet::getString, value -> component.put("project", value));
        maybeSet(rs, "componentUuid", ResultSet::getString, value -> component.put("uuid", value));
        maybeSet(rs, "componentGroup", ResultSet::getString, value -> component.put("group", value));
        maybeSet(rs, "componentName", ResultSet::getString, value -> component.put("name", value));
        maybeSet(rs, "componentVersion", ResultSet::getString, value -> component.put("version", value));
        maybeSet(rs, "componentCpe", ResultSet::getString, value -> component.put("cpe", value));
        maybeSet(rs, "componentPurl", ResultSet::getString, value -> component.put("purl", value));
        maybeSet(rs, "componentLatestVersion", ResultSet::getString, value -> component.put("latestVersion", value));
        maybeSet(rs, "vulnUuid", ResultSet::getString, value -> vuln.put("uuid", value));
        maybeSet(rs, "vulnId", ResultSet::getString, value -> vuln.put("vulnId", value));
        maybeSet(rs, "vulnSource", ResultSet::getString, value -> vuln.put("source", value));
        maybeSet(rs, "vulnTitle", ResultSet::getString, value -> vuln.put("title", value));
        maybeSet(rs, "vulnSubTitle", ResultSet::getString, value -> vuln.put("subtitle", value));
        maybeSet(rs, "vulnDescription", ResultSet::getString, value -> vuln.put("description", value));
        maybeSet(rs, "vulnRecommendation", ResultSet::getString, value -> vuln.put("recommendation", value));
        maybeSet(rs, "vulnCvssV2BaseScore", RowMapperUtil::nullableDouble, value -> vuln.put("cvssV2BaseScore", value));
        maybeSet(rs, "vulnCvssV3BaseScore", RowMapperUtil::nullableDouble, value -> vuln.put("cvssV3BaseScore", value));
        maybeSet(rs, "vulnOwaspRrBusinessImpactScore", RowMapperUtil::nullableDouble, value -> vuln.put("owaspBusinessImpactScore", value));
        maybeSet(rs, "vulnOwaspRrLikelihoodScore", RowMapperUtil::nullableDouble, value -> vuln.put("owaspLikelihoodScore", value));
        maybeSet(rs, "vulnOwaspRrTechnicalImpactScore", RowMapperUtil::nullableDouble, value -> vuln.put("owaspTechnicalImpactScore", value));
        maybeSet(rs, "vulnSeverity", ResultSet::getString, value -> {
            final Severity severity = Severity.valueOf(value);
            vuln.put("severity", severity.name());
            vuln.put("severityRank", severity.ordinal());
        });
        maybeSet(rs, "vulnEpssScore", RowMapperUtil::nullableDouble, value -> vuln.put("epssScore", value));
        maybeSet(rs, "vulnEpssPercentile", RowMapperUtil::nullableDouble, value -> vuln.put("epssPercentile", value));
        maybeSet(rs, "vulnCwes", FindingRowMapper::maybeConvertCwes, value -> {
            vuln.put("cwes", value);

            // Ensure backwards-compatibility with DT < 4.5.0.
            // TODO: This is scheduled for removal in v5.
            //  Remove in separate PR and make sure to document it!
            if (!value.isEmpty()) {
                final Cwe firstCwe = value.get(0);
                vuln.put("cweId", firstCwe.getCweId());
                vuln.put("cweName", firstCwe.getName());
            }
        });
        maybeSet(rs, "vulnAliases", FindingRowMapper::maybeConvertAliases, value -> vuln.put("aliases", value));
        maybeSet(rs, "analyzerIdentity", ResultSet::getString, value -> attribution.put("analyzerIdentity", value));
        maybeSet(rs, "attributedOn", ResultSet::getTimestamp, value -> attribution.put("attributedOn", value));
        maybeSet(rs, "alternateIdentifier", ResultSet::getString, value -> attribution.put("alternateIdentifier", value));
        maybeSet(rs, "referenceUrl", ResultSet::getString, value -> attribution.put("referenceUrl", value));
        maybeSet(rs, "analysisState", ResultSet::getString, value -> analysis.put("state", value));
        analysis.put("isSuppressed", rs.getBoolean("isSuppressed"));

        return new Finding(analysis, attribution, component, vuln);
    }

    private static List<Cwe> maybeConvertCwes(final ResultSet rs, final String columnName) throws SQLException {
        return stringArray(rs, columnName).stream()
                .map(CweResolver.getInstance()::lookup)
                .filter(Objects::nonNull)
                .toList();
    }

    private static Set<Map<String, String>> maybeConvertAliases(final ResultSet rs, final String columnName) throws SQLException {
        final List<VulnerabilityAlias> aliases = deserializeJson(rs, columnName, VULNERABILITY_ALIASES_TYPE_REF);
        if (aliases == null) {
            return Collections.emptySet();
        }

        final Set<Map<String, String>> uniqueAliases = new HashSet<>();
        for (final VulnerabilityAlias alias : aliases) {
            Map<String, String> map = new HashMap<>();
            if (alias.getCveId() != null && !alias.getCveId().isBlank()) {
                map.put("cveId", alias.getCveId());
            }
            if (alias.getGhsaId() != null && !alias.getGhsaId().isBlank()) {
                map.put("ghsaId", alias.getGhsaId());
            }
            if (alias.getSonatypeId() != null && !alias.getSonatypeId().isBlank()) {
                map.put("sonatypeId", alias.getSonatypeId());
            }
            if (alias.getOsvId() != null && !alias.getOsvId().isBlank()) {
                map.put("osvId", alias.getOsvId());
            }
            if (alias.getSnykId() != null && !alias.getSnykId().isBlank()) {
                map.put("snykId", alias.getSnykId());
            }
            if (alias.getVulnDbId() != null && !alias.getVulnDbId().isBlank()) {
                map.put("vulnDbId", alias.getVulnDbId());
            }
            uniqueAliases.add(map);
        }

        return uniqueAliases;
    }

}
