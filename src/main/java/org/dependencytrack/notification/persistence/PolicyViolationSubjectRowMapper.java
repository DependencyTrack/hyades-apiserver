package org.dependencytrack.notification.persistence;

import org.dependencytrack.proto.notification.v1.Component;
import org.dependencytrack.proto.notification.v1.Policy;
import org.dependencytrack.proto.notification.v1.PolicyCondition;
import org.dependencytrack.proto.notification.v1.PolicyViolation;
import org.dependencytrack.proto.notification.v1.PolicyViolationSubject;
import org.dependencytrack.proto.notification.v1.Project;
import org.jdbi.v3.core.mapper.RowMapper;
import org.jdbi.v3.core.statement.StatementContext;

import java.sql.ResultSet;
import java.sql.SQLException;

public class PolicyViolationSubjectRowMapper implements RowMapper<PolicyViolationSubject> {

    @Override
    public PolicyViolationSubject map(final ResultSet rs, final StatementContext ctx) throws SQLException {
        final RowMapper<Component> componentRowMapper = ctx.findRowMapperFor(Component.class).orElseThrow();
        final RowMapper<Project> projectRowMapper = ctx.findRowMapperFor(Project.class).orElseThrow();
        final RowMapper<Policy> policyRowMapper = ctx.findRowMapperFor(Policy.class).orElseThrow();
        final RowMapper<PolicyCondition> conditionRowMapper = ctx.findRowMapperFor(PolicyCondition.class).orElseThrow();
        final RowMapper<PolicyViolation> violationRowMapper = ctx.findRowMapperFor(PolicyViolation.class).orElseThrow();

        return PolicyViolationSubject.newBuilder()
                .setComponent(componentRowMapper.map(rs, ctx))
                .setProject(projectRowMapper.map(rs, ctx))
                .setPolicyViolation(violationRowMapper.map(rs, ctx).toBuilder()
                        .setCondition(conditionRowMapper.map(rs, ctx).toBuilder()
                                .setPolicy(policyRowMapper.map(rs, ctx))
                                .build())
                        .build())
                .build();
    }

}
