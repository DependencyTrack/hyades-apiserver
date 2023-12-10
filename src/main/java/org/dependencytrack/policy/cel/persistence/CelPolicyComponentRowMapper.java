package org.dependencytrack.policy.cel.persistence;

import com.google.protobuf.util.Timestamps;
import org.dependencytrack.proto.policy.v1.Component;
import org.jdbi.v3.core.mapper.RowMapper;
import org.jdbi.v3.core.statement.StatementContext;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Date;

import static org.dependencytrack.policy.cel.persistence.CelPolicyRowMapperUtil.maybeSet;

public class CelPolicyComponentRowMapper implements RowMapper<Component> {

    private final Component.Builder builder;

    public CelPolicyComponentRowMapper() {
        this(Component.newBuilder());
    }

    CelPolicyComponentRowMapper(final Component.Builder builder) {
        this.builder = builder;
    }

    @Override
    public Component map(final ResultSet rs, final StatementContext ctx) throws SQLException {
        maybeSet(rs, "uuid", rs::getString, builder::setUuid);
        maybeSet(rs, "group", rs::getString, builder::setGroup);
        maybeSet(rs, "name", rs::getString, builder::setName);
        maybeSet(rs, "version", rs::getString, builder::setVersion);
        maybeSet(rs, "classifier", rs::getString, builder::setClassifier);
        maybeSet(rs, "cpe", rs::getString, builder::setCpe);
        maybeSet(rs, "purl", rs::getString, builder::setPurl);
        maybeSet(rs, "swid_tag_id", rs::getString, builder::setSwidTagId);
        maybeSet(rs, "is_internal", rs::getBoolean, builder::setIsInternal);
        maybeSet(rs, "md5", rs::getString, builder::setMd5);
        maybeSet(rs, "sha1", rs::getString, builder::setSha1);
        maybeSet(rs, "sha256", rs::getString, builder::setSha256);
        maybeSet(rs, "sha384", rs::getString, builder::setSha384);
        maybeSet(rs, "sha512", rs::getString, builder::setSha512);
        maybeSet(rs, "sha3_256", rs::getString, builder::setSha3256);
        maybeSet(rs, "sha3_384", rs::getString, builder::setSha3384);
        maybeSet(rs, "sha3_512", rs::getString, builder::setSha3512);
        maybeSet(rs, "license_name", rs::getString, builder::setLicenseName);
        maybeSet(rs, "license_expression", rs::getString, builder::setLicenseExpression);
        maybeSet(rs, "published_at", columnName -> {
            final Date lastBomImport = rs.getTimestamp(columnName);
            return lastBomImport != null ? Timestamps.fromDate(lastBomImport) : null;
        }, builder::setPublishedAt);
        maybeSet(rs, "latest_version", rs::getString, builder::setLatestVersion);
        return builder.build();
    }
}
