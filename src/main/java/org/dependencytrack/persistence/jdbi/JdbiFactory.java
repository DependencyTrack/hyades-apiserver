/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.persistence.jdbi;

import alpine.resources.AlpineRequest;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.datanucleus.api.jdo.JDOPersistenceManagerFactory;
import org.datanucleus.store.connection.ConnectionManagerImpl;
import org.datanucleus.store.rdbms.ConnectionFactoryImpl;
import org.datanucleus.store.rdbms.RDBMSStoreManager;
import org.dependencytrack.persistence.QueryManager;
import org.jdbi.v3.core.Handle;
import org.jdbi.v3.core.HandleCallback;
import org.jdbi.v3.core.HandleConsumer;
import org.jdbi.v3.core.Jdbi;
import org.jdbi.v3.freemarker.FreemarkerEngine;
import org.jdbi.v3.jackson2.Jackson2Config;
import org.jdbi.v3.jackson2.Jackson2Plugin;
import org.jdbi.v3.postgres.PostgresPlugin;
import org.jdbi.v3.sqlobject.SqlObjectPlugin;

import javax.jdo.PersistenceManager;
import javax.jdo.PersistenceManagerFactory;
import javax.sql.DataSource;
import java.sql.Connection;
import java.util.concurrent.atomic.AtomicReference;

import static org.apache.commons.lang3.reflect.FieldUtils.readField;

public class JdbiFactory {

    private static final AtomicReference<GlobalInstanceHolder> GLOBAL_INSTANCE_HOLDER = new AtomicReference<>();

    public static Handle openJdbiHandle() {
        return createJdbi().open();
    }

    public static Handle openJdbiHandle(final AlpineRequest alpineRequest) {
        return forApiRequest(createJdbi().open(), alpineRequest);
    }

    public static <X extends Exception> void useJdbiHandle(final HandleConsumer<X> handleConsumer) throws X {
        createJdbi().useHandle(handleConsumer);
    }

    public static <X extends Exception> void useJdbiHandle(final AlpineRequest apiRequest, final HandleConsumer<X> handleConsumer) throws X {
        createJdbi().useHandle(handle -> handleConsumer.useHandle(forApiRequest(handle, apiRequest)));
    }

    public static <T, X extends Exception> T withJdbiHandle(final HandleCallback<T, X> handleCallback) throws X {
        return createJdbi().withHandle(handleCallback);
    }

    public static <T, X extends Exception> T withJdbiHandle(final AlpineRequest apiRequest, final HandleCallback<T, X> handleCallback) throws X {
        return createJdbi().withHandle(handle -> handleCallback.withHandle(forApiRequest(handle, apiRequest)));
    }

    public static <X extends Exception> void useJdbiTransaction(final HandleConsumer<X> handleConsumer) throws X {
        createJdbi().useTransaction(handleConsumer);
    }

    public static <X extends Exception> void useJdbiTransaction(final AlpineRequest apiRequest, final HandleConsumer<X> handleConsumer) throws X {
        createJdbi().useTransaction(handle -> handleConsumer.useHandle(forApiRequest(handle, apiRequest)));
    }

    public static <T, X extends Exception> T inJdbiTransaction(final HandleCallback<T, X> handleCallback) throws X {
        return createJdbi().inTransaction(handleCallback);
    }

    public static <T, X extends Exception> T inJdbiTransaction(final AlpineRequest apiRequest, final HandleCallback<T, X> handleCallback) throws X {
        return createJdbi().inTransaction(handle -> handleCallback.withHandle(forApiRequest(handle, apiRequest)));
    }

    private static Handle forApiRequest(final Handle handle, final AlpineRequest apiRequest) {
        return handle.addCustomizer(new ApiRequestStatementCustomizer(apiRequest));
    }

    /**
     * Get a global {@link Jdbi} instance, initializing it if it hasn't been initialized before.
     * <p>
     * The global instance will use {@link Connection}s from the primary {@link DataSource}
     * of a {@link PersistenceManager}'s {@link PersistenceManagerFactory}.
     * <p>
     * Usage of the global instance should be preferred to make the best possible use of JDBI's
     * internal caching mechanisms. However, this instance can't participate in transactions
     * initiated by JDO (via {@link QueryManager} or {@link PersistenceManager}).
     * <p>
     * If {@link Jdbi} usage in an active JDO {@link javax.jdo.Transaction} is desired,
     * use {@link #createLocalJdbi(QueryManager)} instead, which will use the same {@link Connection}
     * as the provided {@link QueryManager}.
     *
     * @return The global {@link Jdbi} instance
     */
    static Jdbi createJdbi() {
        // NB: The PersistenceManager is only required to gain access to the underlying
        // datasource. It must be closed to avoid resource leakage, but the JDBI instance
        // will continue to work.
        try (final PersistenceManager pm = alpine.server.persistence.PersistenceManagerFactory.createPersistenceManager()) {
            return createJdbi(pm);
        }
    }

    private static Jdbi createJdbi(final PersistenceManager pm) {
        return GLOBAL_INSTANCE_HOLDER
                .updateAndGet(previous -> {
                    if (previous == null || previous.pmf != pm.getPersistenceManagerFactory()) {
                        // The PMF reference does not usually change, unless it has been recreated,
                        // or multiple PMFs exist in the same application. The latter is not the case
                        // for Dependency-Track, and the former only happens during test execution,
                        // where each test (re-)creates the PMF.
                        final Jdbi jdbi = createFromPmf(pm.getPersistenceManagerFactory());
                        return new GlobalInstanceHolder(jdbi, pm.getPersistenceManagerFactory());
                    }

                    return previous;
                })
                .jdbi();
    }

    /**
     * Create a new local {@link Jdbi} instance.
     * <p>
     * The instance will use the same {@link Connection} used by the given {@link QueryManager},
     * allowing it to participate in {@link javax.jdo.Transaction}s initiated by {@code qm}.
     * <p>
     * Because using local {@link Jdbi} instances has a high performance impact (e.g. due to ineffective caching),
     * this method will throw if {@code qm} is not participating in an active {@link javax.jdo.Transaction}
     * already.
     * <p>
     * Just like {@link QueryManager} itself, {@link Jdbi} instances created by this method are <em>not</em>
     * thread safe!
     *
     * @param qm The {@link QueryManager} to use the underlying {@link Connection} of
     * @return A new {@link Jdbi} instance
     * @throws IllegalStateException When the given {@link QueryManager} is not participating
     *                               in an active {@link javax.jdo.Transaction}
     */
    static Jdbi createLocalJdbi(final QueryManager qm) {
        return createLocalJdbi(qm.getPersistenceManager());
    }

    private static Jdbi createLocalJdbi(final PersistenceManager pm) {
        if (!pm.currentTransaction().isActive()) {
            throw new IllegalStateException("""
                    Local JDBI instances must not be used outside of an active JDO transaction. \
                    Use the global instance instead if combining JDBI with JDO transactions is not needed.""");
        }

        return customizeJdbi(Jdbi.create(new JdoConnectionFactory(pm)));
    }

    private record GlobalInstanceHolder(Jdbi jdbi, PersistenceManagerFactory pmf) {
    }

    private static Jdbi createFromPmf(final PersistenceManagerFactory pmf) {
        try {
            if (pmf instanceof final JDOPersistenceManagerFactory jdoPmf
                && jdoPmf.getNucleusContext().getStoreManager() instanceof final RDBMSStoreManager storeManager
                && storeManager.getConnectionManager() instanceof final ConnectionManagerImpl connectionManager
                && readField(connectionManager, "primaryConnectionFactory", true) instanceof ConnectionFactoryImpl connectionFactory
                && readField(connectionFactory, "dataSource", true) instanceof final DataSource dataSource) {
                return customizeJdbi(Jdbi.create(dataSource));
            }
        } catch (IllegalAccessException e) {
            throw new IllegalStateException("Failed to access datasource of PMF via reflection", e);
        }

        throw new IllegalStateException("Failed to access primary datasource of PMF");
    }

    private static Jdbi customizeJdbi(final Jdbi jdbi) {
        final Jdbi preparedJdbi = jdbi
                .installPlugin(new SqlObjectPlugin())
                .installPlugin(new PostgresPlugin())
                .installPlugin(new Jackson2Plugin())
                .setTemplateEngine(FreemarkerEngine.instance());

        preparedJdbi.getConfig(Jackson2Config.class).setMapper(createJsonMapper());
        return preparedJdbi;
    }

    private static JsonMapper createJsonMapper() {
        return JsonMapper.builder()
                // Avoid unnecessary @JsonAlias or "SELECT ... AS ..." statements
                // for mapping upper-cased columns to camel-cased Java fields.
                .enable(MapperFeature.ACCEPT_CASE_INSENSITIVE_PROPERTIES)
                .addModule(new JavaTimeModule())
                .build();
    }

}
