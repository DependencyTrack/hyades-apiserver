package org.dependencytrack.persistence.jdbi.mapping;

import com.fasterxml.jackson.core.type.TypeReference;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.AnalyzerIdentity;
import org.dependencytrack.model.Cwe;
import org.dependencytrack.model.Finding;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAlias;
import org.dependencytrack.parser.common.resolver.CweResolver;
import org.jdbi.v3.core.mapper.RowMapper;
import org.jdbi.v3.core.statement.StatementContext;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

import static org.dependencytrack.persistence.jdbi.mapping.RowMapperUtil.deserializeJson;
import static org.dependencytrack.persistence.jdbi.mapping.RowMapperUtil.maybeSet;
import static org.dependencytrack.persistence.jdbi.mapping.RowMapperUtil.stringArray;

public class FindingRowMapper implements RowMapper<Finding> {

    private static final TypeReference<List<VulnerabilityAlias>> VULNERABILITY_ALIASES_TYPE_REF = new TypeReference<>() {
    };

    @Override
    public Finding map(final ResultSet rs, final StatementContext ctx) throws SQLException {
        final var analysis = new Finding.Analysis();
        final var attribution = new Finding.Attribution();
        final var component = new Finding.Component();
        final var vuln = new Finding.Vulnerability();

        maybeSet(rs, "projectUuid", ResultSet::getString, value -> component.setProject(UUID.fromString(value)));
        maybeSet(rs, "componentUuid", ResultSet::getString, value -> component.setUuid(UUID.fromString(value)));
        maybeSet(rs, "componentGroup", ResultSet::getString, component::setGroup);
        maybeSet(rs, "componentName", ResultSet::getString, component::setName);
        maybeSet(rs, "componentVersion", ResultSet::getString, component::setVersion);
        maybeSet(rs, "componentCpe", ResultSet::getString, component::setCpe);
        maybeSet(rs, "componentPurl", ResultSet::getString, component::setPurl);
        maybeSet(rs, "componentLatestVersion", ResultSet::getString, component::setLatestVersion);
        maybeSet(rs, "vulnUuid", ResultSet::getString, value -> vuln.setUuid(UUID.fromString(value)));
        maybeSet(rs, "vulnId", ResultSet::getString, vuln::setVulnId);
        maybeSet(rs, "vulnSource", ResultSet::getString, value -> vuln.setSource(Vulnerability.Source.valueOf(value)));
        maybeSet(rs, "vulnTitle", ResultSet::getString, vuln::setTitle);
        maybeSet(rs, "vulnSubTitle", ResultSet::getString, vuln::setSubtitle);
        maybeSet(rs, "vulnDescription", ResultSet::getString, vuln::setDescription);
        maybeSet(rs, "vulnRecommendation", ResultSet::getString, vuln::setRecommendation);
        maybeSet(rs, "vulnCvssV2BaseScore", RowMapperUtil::nullableDouble, vuln::setCvssV2BaseScore);
        maybeSet(rs, "vulnCvssV3BaseScore", RowMapperUtil::nullableDouble, vuln::setCvssV3BaseScore);
        maybeSet(rs, "vulnOwaspRrBusinessImpactScore", RowMapperUtil::nullableDouble, vuln::setOwaspBusinessImpactScore);
        maybeSet(rs, "vulnOwaspRrLikelihoodScore", RowMapperUtil::nullableDouble, vuln::setOwaspLikelihoodScore);
        maybeSet(rs, "vulnOwaspRrTechnicalImpactScore", RowMapperUtil::nullableDouble, vuln::setOwaspTechnicalImpactScore);
        maybeSet(rs, "vulnSeverity", ResultSet::getString, value -> vuln.setSeverity(Severity.valueOf(value)));
        maybeSet(rs, "vulnEpssScore", RowMapperUtil::nullableDouble, vuln::setEpssScore);
        maybeSet(rs, "vulnEpssPercentile", RowMapperUtil::nullableDouble, vuln::setEpssPercentile);
        maybeSet(rs, "vulnCwes", FindingRowMapper::maybeConvertCwes, value -> {
            vuln.setCwes(value);

            // Ensure backwards-compatibility with DT < 4.5.0.
            // TODO: This is scheduled for removal in v5.
            //  Remove in separate PR and make sure to document it!
            if (!value.isEmpty()) {
                final Cwe firstCwe = value.get(0);
                vuln.setCweId(firstCwe.getCweId());
                vuln.setCweName(firstCwe.getName());
            }
        });
        maybeSet(rs, "vulnAliases", FindingRowMapper::maybeConvertAliases, vuln::addVulnerabilityAliases);
        maybeSet(rs, "analyzerIdentity", ResultSet::getString, value -> attribution.setAnalyzerIdentity(AnalyzerIdentity.valueOf(value)));
        maybeSet(rs, "attributedOn", ResultSet::getTimestamp, attribution::setAttributedOn);
        maybeSet(rs, "alternateIdentifier", ResultSet::getString, attribution::setAlternateIdentifier);
        maybeSet(rs, "referenceUrl", ResultSet::getString, attribution::setReferenceUrl);
        maybeSet(rs, "analysisState", ResultSet::getString, value -> analysis.setState(AnalysisState.valueOf(value)));
        analysis.setSuppressed(rs.getBoolean("isSuppressed"));

        return new Finding(analysis, attribution, component, vuln);
    }

    private static List<Cwe> maybeConvertCwes(final ResultSet rs, final String columnName) throws SQLException {
        return stringArray(rs, columnName).stream()
                .map(CweResolver.getInstance()::lookup)
                .filter(Objects::nonNull)
                .toList();
    }

    private static List<VulnerabilityAlias> maybeConvertAliases(final ResultSet rs, final String columnName) throws SQLException {
        final List<VulnerabilityAlias> aliases = deserializeJson(rs, columnName, VULNERABILITY_ALIASES_TYPE_REF);
        if (aliases == null) {
            return Collections.emptyList();
        }

        return aliases;
    }

}
