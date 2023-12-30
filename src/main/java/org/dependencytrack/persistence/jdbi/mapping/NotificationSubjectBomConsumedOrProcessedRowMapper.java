package org.dependencytrack.persistence.jdbi.mapping;

import org.dependencytrack.proto.notification.v1.Bom;
import org.dependencytrack.proto.notification.v1.BomConsumedOrProcessedSubject;
import org.dependencytrack.proto.notification.v1.Project;
import org.jdbi.v3.core.mapper.NoSuchMapperException;
import org.jdbi.v3.core.mapper.RowMapper;
import org.jdbi.v3.core.statement.StatementContext;

import java.sql.ResultSet;
import java.sql.SQLException;

import static org.dependencytrack.persistence.jdbi.mapping.RowMapperUtil.maybeSet;

public class NotificationSubjectBomConsumedOrProcessedRowMapper implements RowMapper<BomConsumedOrProcessedSubject> {

    @Override
    public BomConsumedOrProcessedSubject map(final ResultSet rs, final StatementContext ctx) throws SQLException {
        final RowMapper<Project> projectRowMapper = ctx.findRowMapperFor(Project.class)
                .orElseThrow(() -> new NoSuchMapperException("No mapper registered for %s".formatted(Project.class)));
        final RowMapper<Bom> bomRowMapper = ctx.findRowMapperFor(Bom.class)
                .orElseThrow(() -> new NoSuchMapperException("No mapper registered for %s".formatted(Bom.class)));

        final BomConsumedOrProcessedSubject.Builder builder = BomConsumedOrProcessedSubject.newBuilder()
                .setProject(projectRowMapper.map(rs, ctx))
                .setBom(bomRowMapper.map(rs, ctx));
        maybeSet(rs, "token", ResultSet::getString, builder::setToken);

        return builder.build();
    }

}
