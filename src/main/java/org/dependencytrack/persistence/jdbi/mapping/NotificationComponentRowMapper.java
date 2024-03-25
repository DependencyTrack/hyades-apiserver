package org.dependencytrack.persistence.jdbi.mapping;

import org.dependencytrack.proto.notification.v1.Component;
import org.jdbi.v3.core.mapper.RowMapper;
import org.jdbi.v3.core.statement.StatementContext;

import java.sql.ResultSet;
import java.sql.SQLException;

import static org.dependencytrack.persistence.jdbi.mapping.RowMapperUtil.maybeSet;

public class NotificationComponentRowMapper implements RowMapper<Component> {

    @Override
    public Component map(final ResultSet rs, final StatementContext ctx) throws SQLException {
        final Component.Builder builder = Component.newBuilder();
        maybeSet(rs, "componentUuid", ResultSet::getString, builder::setUuid);
        maybeSet(rs, "componentGroup", ResultSet::getString, builder::setGroup);
        maybeSet(rs, "componentName", ResultSet::getString, builder::setName);
        maybeSet(rs, "componentVersion", ResultSet::getString, builder::setVersion);
        maybeSet(rs, "componentPurl", ResultSet::getString, builder::setPurl);
        maybeSet(rs, "componentMd5", ResultSet::getString, builder::setMd5);
        maybeSet(rs, "componentSha1", ResultSet::getString, builder::setSha1);
        maybeSet(rs, "componentSha256", ResultSet::getString, builder::setSha256);
        maybeSet(rs, "componentSha512", ResultSet::getString, builder::setSha512);
        return builder.build();
    }

}
