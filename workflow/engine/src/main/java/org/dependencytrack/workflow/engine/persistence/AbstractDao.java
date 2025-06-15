package org.dependencytrack.workflow.engine.persistence;

import org.dependencytrack.workflow.engine.api.pagination.InvalidPageTokenException;
import org.jdbi.v3.core.Handle;
import org.jdbi.v3.core.result.UnableToProduceResultException;
import org.jdbi.v3.json.JsonConfig;
import org.jdbi.v3.json.JsonMapper.TypedJsonMapper;
import org.jspecify.annotations.Nullable;

import java.util.Base64;

abstract class AbstractDao {

    final Handle jdbiHandle;

    AbstractDao(final Handle jdbiHandle) {
        this.jdbiHandle = jdbiHandle;
    }

    @Nullable
    <T> String encodePageToken(@Nullable final T token) {
        if (token == null) {
            return null;
        }

        final TypedJsonMapper jsonMapper = jdbiHandle
                .getConfig(JsonConfig.class)
                .getJsonMapper()
                .forType(token.getClass(), jdbiHandle.getConfig());

        final String pageTokenJson = jsonMapper.toJson(token, jdbiHandle.getConfig());
        return Base64.getUrlEncoder().encodeToString(pageTokenJson.getBytes());
    }

    @Nullable
    @SuppressWarnings("unchecked")
    <T> T decodePageToken(@Nullable final String token, final Class<T> tokenClass) {
        if (token == null || token.isBlank()) {
            return null;
        }

        final TypedJsonMapper jsonMapper = jdbiHandle
                .getConfig(JsonConfig.class)
                .getJsonMapper()
                .forType(tokenClass, jdbiHandle.getConfig());

        try {
            final byte[] tokenBytes = Base64.getUrlDecoder().decode(token);
            return (T) jsonMapper.fromJson(new String(tokenBytes), jdbiHandle.getConfig());
        } catch (IllegalArgumentException | UnableToProduceResultException e) {
            throw new InvalidPageTokenException(e);
        }
    }

}
