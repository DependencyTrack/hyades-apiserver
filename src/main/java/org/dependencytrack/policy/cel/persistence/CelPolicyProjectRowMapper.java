package org.dependencytrack.policy.cel.persistence;

import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.core.type.TypeReference;
import com.google.protobuf.util.JsonFormat;
import com.google.protobuf.util.Timestamps;
import org.dependencytrack.proto.policy.v1.Project;
import org.jdbi.v3.core.mapper.RowMapper;
import org.jdbi.v3.core.statement.StatementContext;

import java.io.IOException;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.function.Consumer;

import static org.dependencytrack.policy.cel.persistence.CelPolicyRowMapperUtil.OBJECT_MAPPER;
import static org.dependencytrack.policy.cel.persistence.CelPolicyRowMapperUtil.hasColumn;
import static org.dependencytrack.policy.cel.persistence.CelPolicyRowMapperUtil.maybeSet;

public class CelPolicyProjectRowMapper implements RowMapper<Project> {

    private final Project.Builder builder;

    public CelPolicyProjectRowMapper() {
        this(Project.newBuilder());
    }

    public CelPolicyProjectRowMapper(final Project.Builder builder) {
        this.builder = builder;
    }

    @Override
    public Project map(final ResultSet rs, final StatementContext ctx) throws SQLException {
        maybeSet(rs, "uuid", rs::getString, builder::setUuid);
        maybeSet(rs, "group", rs::getString, builder::setGroup);
        maybeSet(rs, "name", rs::getString, builder::setName);
        maybeSet(rs, "version", rs::getString, builder::setVersion);
        maybeSet(rs, "classifier", rs::getString, builder::setClassifier);
        maybeSet(rs, "is_active", rs::getBoolean, builder::setIsActive);
        maybeSetTags(rs, builder::addAllTags);
        maybeSetProperties(rs, builder::addAllProperties);
        maybeSet(rs, "cpe", rs::getString, builder::setCpe);
        maybeSet(rs, "purl", rs::getString, builder::setPurl);
        maybeSet(rs, "swid_tag_id", rs::getString, builder::setSwidTagId);
        maybeSet(rs, "last_bom_import", columnName -> {
            final Date lastBomImport = rs.getDate(columnName);
            return lastBomImport != null ? Timestamps.fromDate(lastBomImport) : null;
        }, builder::setLastBomImport);
        return builder.build();
    }

    private void maybeSetTags(final ResultSet rs, final Consumer<List<String>> setter) throws SQLException {
        if (!hasColumn(rs, "tags")) {
            return;
        }

        try {
            final List<String> tags = OBJECT_MAPPER.readValue(rs.getString("tags"), new TypeReference<>() {
            });
            setter.accept(tags);
        } catch (JacksonException e) {
            throw new RuntimeException(e);
        }
    }

    private void maybeSetProperties(final ResultSet rs, final Consumer<List<Project.Property>> setter) throws SQLException {
        if (!hasColumn(rs, "properties")) {
            return;
        }

        final var properties = new ArrayList<Project.Property>();
        try (final JsonParser jsonParser = OBJECT_MAPPER.createParser(rs.getString("properties"))) {
            JsonToken currentToken = jsonParser.nextToken(); // Position cursor at first token.
            if (currentToken != JsonToken.START_ARRAY) {
                return;
            }

            while (jsonParser.nextToken() != JsonToken.END_ARRAY) {
                currentToken = jsonParser.nextToken();
                if (currentToken == JsonToken.START_OBJECT) {
                    final var builder = Project.Property.newBuilder();
                    JsonFormat.parser().merge(jsonParser.getValueAsString(), builder);
                    properties.add(builder.build());
                } else {
                    jsonParser.skipChildren();
                }
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        setter.accept(properties);
    }

}
