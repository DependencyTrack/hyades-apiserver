package org.dependencytrack.persistence.pagination;

import alpine.security.crypto.DataEncryption;
import jakarta.ws.rs.core.UriInfo;
import org.dependencytrack.api.v2.model.PaginationLinks;
import org.dependencytrack.api.v2.model.PaginationMetadata;
import org.jdbi.v3.core.Handle;
import org.jdbi.v3.json.JsonConfig;
import org.jdbi.v3.json.JsonMapper;

import java.util.Base64;

public final class PageUtil {

    private PageUtil() {}

    public static <T> T decodePageToken(final Handle handle, final String encodedToken, final Class<T> tokenClass) {
        if (encodedToken == null) {
            return null;
        }

        final JsonMapper.TypedJsonMapper jsonMapper = handle
                .getConfig(JsonConfig.class)
                .getJsonMapper()
                .forType(tokenClass, handle.getConfig());

        try {
            final byte[] encryptedTokenBytes = Base64.getUrlDecoder().decode(encodedToken);
            final byte[] decryptedToken = DataEncryption.decryptAsBytes(encryptedTokenBytes);
            return (T) jsonMapper.fromJson(new String(decryptedToken), handle.getConfig());
        } catch (Exception e) {
            throw new InvalidPageTokenException(e);
        }
    }

    public static <T> String encodePageToken(final Handle handle, final T pageToken) {
        if (pageToken == null) {
            return null;
        }

        final JsonMapper.TypedJsonMapper jsonMapper = handle
                .getConfig(JsonConfig.class)
                .getJsonMapper()
                .forType(Object.class, handle.getConfig());

        try {
            final String tokenJson = jsonMapper.toJson(pageToken, handle.getConfig());
            final byte[] encryptedTokenBytes = DataEncryption.encryptAsBytes(tokenJson);
            return Base64.getUrlEncoder().encodeToString(encryptedTokenBytes);
        } catch (Exception e) {
            throw new InvalidPageTokenException(e);
        }
    }

    public static PaginationMetadata createPaginationMetadata(final UriInfo uriInfo, final Page<?> page) {
        return PaginationMetadata.builder()
                .links(PaginationLinks.builder()
                        .self(uriInfo.getRequestUri())
                        .next(page.nextPageToken() != null ?
                                uriInfo.getRequestUriBuilder()
                                        .queryParam("page_token", page.nextPageToken())
                                        .build()
                                : null)
                        .build())
                .build();
    }
}
