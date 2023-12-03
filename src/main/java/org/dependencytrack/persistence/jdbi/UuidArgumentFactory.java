package org.dependencytrack.persistence.jdbi;

import org.jdbi.v3.core.argument.AbstractArgumentFactory;
import org.jdbi.v3.core.argument.Argument;
import org.jdbi.v3.core.config.ConfigRegistry;

import java.sql.Types;
import java.util.UUID;

/**
 * An {@link org.jdbi.v3.core.argument.ArgumentFactory} that binds {@link UUID}s
 * as {@link String}s instead of the database-native UUID type.
 */
public class UuidArgumentFactory extends AbstractArgumentFactory<UUID> {

    public UuidArgumentFactory() {
        super(Types.VARCHAR);
    }

    @Override
    protected Argument build(final UUID value, final ConfigRegistry config) {
        return (position, statement, ctx) -> {
            if (value == null) {
                statement.setString(position, null);
            } else {
                statement.setString(position, value.toString());
            }
        };
    }

}
