package org.dependencytrack.persistence.jdbi.mapping;

import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.proto.notification.v1.Project;
import org.jdbi.v3.core.mapper.RowMapper;
import org.jdbi.v3.core.statement.StatementContext;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;

import static org.apache.commons.lang3.StringUtils.trimToEmpty;

public class NotificationProjectRowMapper implements RowMapper<Project> {

    @Override
    public Project map(final ResultSet rs, final StatementContext ctx) throws SQLException {
        return Project.newBuilder()
                .setUuid(trimToEmpty(rs.getString("projectUuid")))
                .setName(trimToEmpty(rs.getString("projectName")))
                .setVersion(trimToEmpty(rs.getString("projectVersion")))
                .setDescription(trimToEmpty(rs.getString("projectDescription")))
                .setPurl(trimToEmpty(rs.getString("projectPurl")))
                .addAllTags(Optional.ofNullable(rs.getString("projectTags")).stream()
                        .flatMap(tagNames -> Arrays.stream(tagNames.split(",")))
                        .map(StringUtils::trimToNull)
                        .filter(Objects::nonNull)
                        .toList())
                .build();
    }

}
