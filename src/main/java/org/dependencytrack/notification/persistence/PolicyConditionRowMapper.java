package org.dependencytrack.notification.persistence;

import org.dependencytrack.proto.notification.v1.PolicyCondition;
import org.jdbi.v3.core.mapper.RowMapper;
import org.jdbi.v3.core.statement.StatementContext;

import java.sql.ResultSet;
import java.sql.SQLException;

import static org.apache.commons.lang3.StringUtils.trimToEmpty;

public class PolicyConditionRowMapper implements RowMapper<PolicyCondition> {

    @Override
    public PolicyCondition map(final ResultSet rs, final StatementContext ctx) throws SQLException {
        return PolicyCondition.newBuilder()
                .setUuid(trimToEmpty(rs.getString("conditionUuid")))
                .setSubject(trimToEmpty(rs.getString("conditionSubject")))
                .setOperator(trimToEmpty(rs.getString("conditionOperator")))
                .setValue(trimToEmpty(rs.getString("conditionValue")))
                .build();
    }

}
