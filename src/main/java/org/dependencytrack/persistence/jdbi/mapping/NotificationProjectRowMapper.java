package org.dependencytrack.persistence.jdbi.mapping;

import org.dependencytrack.proto.notification.v1.Project;
import org.jdbi.v3.core.mapper.RowMapper;
import org.jdbi.v3.core.statement.StatementContext;

import java.sql.ResultSet;
import java.sql.SQLException;

import static org.dependencytrack.persistence.jdbi.mapping.RowMapperUtil.maybeSet;

public class NotificationProjectRowMapper implements RowMapper<Project> {

    @Override
    public Project map(final ResultSet rs, final StatementContext ctx) throws SQLException {
        final Project.Builder builder = Project.newBuilder();
        maybeSet(rs, "projectUuid", ResultSet::getString, builder::setUuid);
        maybeSet(rs, "projectName", ResultSet::getString, builder::setName);
        maybeSet(rs, "projectVersion", ResultSet::getString, builder::setVersion);
        maybeSet(rs, "projectDescription", ResultSet::getString, builder::setDescription);
        maybeSet(rs, "projectPurl", ResultSet::getString, builder::setPurl);
        maybeSet(rs, "projectTags", RowMapperUtil::stringArray, builder::addAllTags);
        return builder.build();
    }

}
