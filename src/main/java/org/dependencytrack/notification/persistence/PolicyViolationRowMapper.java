package org.dependencytrack.notification.persistence;

import com.google.protobuf.util.Timestamps;
import org.dependencytrack.proto.notification.v1.PolicyViolation;
import org.jdbi.v3.core.mapper.RowMapper;
import org.jdbi.v3.core.statement.StatementContext;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Optional;

import static org.apache.commons.lang3.StringUtils.trimToEmpty;

public class PolicyViolationRowMapper implements RowMapper<PolicyViolation> {

    @Override
    public PolicyViolation map(final ResultSet rs, final StatementContext ctx) throws SQLException {
        return PolicyViolation.newBuilder()
                .setUuid(trimToEmpty(rs.getString("violationUuid")))
                .setType(trimToEmpty(rs.getString("violationType")))
                .setTimestamp(Optional.ofNullable(rs.getTimestamp("violationTimestamp")).map(Timestamps::fromDate).orElse(Timestamps.EPOCH))
                .build();
    }

}
