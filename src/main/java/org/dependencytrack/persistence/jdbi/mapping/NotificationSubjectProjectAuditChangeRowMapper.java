package org.dependencytrack.persistence.jdbi.mapping;

import org.dependencytrack.proto.notification.v1.Component;
import org.dependencytrack.proto.notification.v1.Project;
import org.dependencytrack.proto.notification.v1.Vulnerability;
import org.dependencytrack.proto.notification.v1.VulnerabilityAnalysis;
import org.dependencytrack.proto.notification.v1.VulnerabilityAnalysisDecisionChangeSubject;
import org.jdbi.v3.core.mapper.RowMapper;
import org.jdbi.v3.core.statement.StatementContext;

import java.sql.ResultSet;
import java.sql.SQLException;

import static org.dependencytrack.persistence.jdbi.mapping.RowMapperUtil.maybeSet;

public class NotificationSubjectProjectAuditChangeRowMapper implements RowMapper<VulnerabilityAnalysisDecisionChangeSubject> {

    @Override
    public VulnerabilityAnalysisDecisionChangeSubject map(final ResultSet rs, final StatementContext ctx) throws SQLException {
        final RowMapper<Component> componentRowMapper = ctx.findRowMapperFor(Component.class).orElseThrow();
        final RowMapper<Project> projectRowMapper = ctx.findRowMapperFor(Project.class).orElseThrow();
        final RowMapper<Vulnerability> vulnRowMapper = ctx.findRowMapperFor(Vulnerability.class).orElseThrow();
        final VulnerabilityAnalysis.Builder vulnAnalysisBuilder = VulnerabilityAnalysis.newBuilder()
                .setComponent(componentRowMapper.map(rs, ctx))
                .setProject(projectRowMapper.map(rs, ctx))
                .setVulnerability(vulnRowMapper.map(rs, ctx));
        maybeSet(rs, "vulnAnalysisState", ResultSet::getString, vulnAnalysisBuilder::setState);
        maybeSet(rs, "isVulnAnalysisSuppressed", ResultSet::getBoolean, vulnAnalysisBuilder::setSuppressed);
        final VulnerabilityAnalysisDecisionChangeSubject.Builder builder = VulnerabilityAnalysisDecisionChangeSubject.newBuilder()
                .setComponent(componentRowMapper.map(rs, ctx))
                .setProject(projectRowMapper.map(rs, ctx))
                .setVulnerability(vulnRowMapper.map(rs, ctx))
                .setAnalysis(vulnAnalysisBuilder);
        return builder.build();
    }

}
