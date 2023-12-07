package org.dependencytrack.persistence.jdbi.mapping;

import org.dependencytrack.proto.notification.v1.Component;
import org.jdbi.v3.core.mapper.RowMapper;
import org.jdbi.v3.core.statement.StatementContext;

import java.sql.ResultSet;
import java.sql.SQLException;

import static org.apache.commons.lang3.StringUtils.trimToEmpty;

public class NotificationComponentRowMapper implements RowMapper<Component> {

    @Override
    public Component map(final ResultSet rs, final StatementContext ctx) throws SQLException {
        return Component.newBuilder()
                .setUuid(trimToEmpty(rs.getString("componentUuid")))
                .setGroup(trimToEmpty(rs.getString("componentGroup")))
                .setName(trimToEmpty(rs.getString("componentName")))
                .setVersion(trimToEmpty(rs.getString("componentVersion")))
                .setPurl(trimToEmpty(rs.getString("componentPurl")))
                .setMd5(trimToEmpty(rs.getString("componentMd5")))
                .setSha1(trimToEmpty(rs.getString("componentSha1")))
                .setSha256(trimToEmpty(rs.getString("componentSha256")))
                .setSha512(trimToEmpty(rs.getString("componentSha512")))
                .build();
    }

}
