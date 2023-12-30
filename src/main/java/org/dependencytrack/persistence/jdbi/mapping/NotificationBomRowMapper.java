package org.dependencytrack.persistence.jdbi.mapping;

import org.dependencytrack.proto.notification.v1.Bom;
import org.jdbi.v3.core.mapper.RowMapper;
import org.jdbi.v3.core.statement.StatementContext;

import java.sql.ResultSet;
import java.sql.SQLException;

import static org.dependencytrack.persistence.jdbi.mapping.RowMapperUtil.maybeSet;

public class NotificationBomRowMapper implements RowMapper<Bom> {

    @Override
    public Bom map(final ResultSet rs, final StatementContext ctx) throws SQLException {
        final Bom.Builder builder = Bom.newBuilder();
        maybeSet(rs, "bomFormat", ResultSet::getString, builder::setFormat);
        maybeSet(rs, "bomSpecVersion", ResultSet::getString, builder::setSpecVersion);
        maybeSet(rs, "bomContent", ResultSet::getString, builder::setContent);
        return builder.build();
    }

}
