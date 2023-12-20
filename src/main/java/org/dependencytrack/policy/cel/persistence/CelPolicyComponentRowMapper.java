package org.dependencytrack.policy.cel.persistence;

import org.dependencytrack.persistence.jdbi.mapping.RowMapperUtil;
import org.dependencytrack.proto.policy.v1.Component;
import org.jdbi.v3.core.mapper.RowMapper;
import org.jdbi.v3.core.statement.StatementContext;

import java.sql.ResultSet;
import java.sql.SQLException;

import static org.dependencytrack.persistence.jdbi.mapping.RowMapperUtil.maybeSet;

public class CelPolicyComponentRowMapper implements RowMapper<Component> {

    @Override
    public Component map(final ResultSet rs, final StatementContext ctx) throws SQLException {
        final Component.Builder builder = Component.newBuilder();
        maybeSet(rs, "uuid", ResultSet::getString, builder::setUuid);
        maybeSet(rs, "group", ResultSet::getString, builder::setGroup);
        maybeSet(rs, "name", ResultSet::getString, builder::setName);
        maybeSet(rs, "version", ResultSet::getString, builder::setVersion);
        maybeSet(rs, "classifier", ResultSet::getString, builder::setClassifier);
        maybeSet(rs, "cpe", ResultSet::getString, builder::setCpe);
        maybeSet(rs, "purl", ResultSet::getString, builder::setPurl);
        maybeSet(rs, "swid_tag_id", ResultSet::getString, builder::setSwidTagId);
        maybeSet(rs, "is_internal", ResultSet::getBoolean, builder::setIsInternal);
        maybeSet(rs, "md5", ResultSet::getString, builder::setMd5);
        maybeSet(rs, "sha1", ResultSet::getString, builder::setSha1);
        maybeSet(rs, "sha256", ResultSet::getString, builder::setSha256);
        maybeSet(rs, "sha384", ResultSet::getString, builder::setSha384);
        maybeSet(rs, "sha512", ResultSet::getString, builder::setSha512);
        maybeSet(rs, "sha3_256", ResultSet::getString, builder::setSha3256);
        maybeSet(rs, "sha3_384", ResultSet::getString, builder::setSha3384);
        maybeSet(rs, "sha3_512", ResultSet::getString, builder::setSha3512);
        maybeSet(rs, "license_name", ResultSet::getString, builder::setLicenseName);
        maybeSet(rs, "license_expression", ResultSet::getString, builder::setLicenseExpression);
        maybeSet(rs, "published_at", RowMapperUtil::nullableTimestamp, builder::setPublishedAt);
        maybeSet(rs, "latest_version", ResultSet::getString, builder::setLatestVersion);
        return builder.build();
    }
}
