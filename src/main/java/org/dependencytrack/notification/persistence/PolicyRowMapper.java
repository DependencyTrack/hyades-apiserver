package org.dependencytrack.notification.persistence;

import org.dependencytrack.proto.notification.v1.Policy;
import org.jdbi.v3.core.mapper.RowMapper;
import org.jdbi.v3.core.statement.StatementContext;

import java.sql.ResultSet;
import java.sql.SQLException;

import static org.apache.commons.lang3.StringUtils.trimToEmpty;

public class PolicyRowMapper implements RowMapper<Policy> {

    @Override
    public Policy map(final ResultSet rs, final StatementContext ctx) throws SQLException {
        return Policy.newBuilder()
                .setUuid(trimToEmpty(rs.getString("policyUuid")))
                .setName(trimToEmpty(rs.getString("policyName")))
                .setViolationState(trimToEmpty(rs.getString("policyViolationState")))
                .build();
    }

}
