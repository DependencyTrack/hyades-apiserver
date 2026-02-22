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
package org.dependencytrack.resources.v2;

import alpine.server.auth.PermissionRequired;
import jakarta.inject.Inject;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.Response;
import org.dependencytrack.api.v2.CsafApi;
import org.dependencytrack.api.v2.model.CreateCsafAggregatorRequest;
import org.dependencytrack.api.v2.model.CreateCsafProviderRequest;
import org.dependencytrack.api.v2.model.ListCsafAggregatorsResponse;
import org.dependencytrack.api.v2.model.ListCsafProvidersResponse;
import org.dependencytrack.api.v2.model.UpdateCsafAggregatorRequest;
import org.dependencytrack.api.v2.model.UpdateCsafProviderRequest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.common.pagination.Page;
import org.dependencytrack.csaf.CsafAggregator;
import org.dependencytrack.csaf.CsafAggregatorDao;
import org.dependencytrack.csaf.CsafProvider;
import org.dependencytrack.csaf.CsafProviderDao;
import org.dependencytrack.csaf.DiscoverCsafProvidersWorkflow;
import org.dependencytrack.csaf.ListCsafAggregatorsQuery;
import org.dependencytrack.csaf.ListCsafProvidersQuery;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.dex.engine.api.request.CreateWorkflowRunRequest;
import org.dependencytrack.exception.AlreadyExistsException;
import org.dependencytrack.proto.internal.workflow.v1.DiscoverCsafProvidersArg;
import org.dependencytrack.resources.AbstractApiResource;
import org.owasp.security.logging.SecurityMarkers;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.UUID;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

/**
 * Resource for CSAF data provider management.
 *
 * @since 5.7.0
 */
@Path("/")
public class CsafResource extends AbstractApiResource implements CsafApi {

    private static final Logger LOGGER = LoggerFactory.getLogger(CsafResource.class);

    private final DexEngine dexEngine;

    @Inject
    CsafResource(DexEngine dexEngine) {
        this.dexEngine = dexEngine;
    }

    @Override
    @PermissionRequired({
            Permissions.Constants.SYSTEM_CONFIGURATION,
            Permissions.Constants.SYSTEM_CONFIGURATION_CREATE
    })
    public Response createCsafAggregator(CreateCsafAggregatorRequest request) {
        final var aggregator = new CsafAggregator(
                request.getUrl(),
                request.getNamespace(),
                request.getName());
        aggregator.setEnabled(request.getEnabled());

        final CsafAggregator createdAggregator = inJdbiTransaction(
                getAlpineRequest(),
                handle -> handle.attach(CsafAggregatorDao.class).create(aggregator));

        LOGGER.info(
                SecurityMarkers.SECURITY_AUDIT,
                "Created CSAF aggregator '{}'",
                createdAggregator.getNamespace());

        return Response
                .created(
                        getUriInfo().getBaseUriBuilder()
                                .path("/csaf-aggregators")
                                .path(createdAggregator.getId().toString())
                                .build())
                .entity(convert(createdAggregator))
                .build();
    }

    @Override
    @PermissionRequired({
            Permissions.Constants.SYSTEM_CONFIGURATION,
            Permissions.Constants.SYSTEM_CONFIGURATION_READ
    })
    public Response getCsafAggregator(UUID id) {
        final CsafAggregator aggregator = withJdbiHandle(
                getAlpineRequest(),
                handle -> handle.attach(CsafAggregatorDao.class).getById(id));
        if (aggregator == null) {
            throw new NotFoundException();
        }

        return Response.ok(convert(aggregator)).build();
    }

    @Override
    @PermissionRequired({
            Permissions.Constants.SYSTEM_CONFIGURATION,
            Permissions.Constants.SYSTEM_CONFIGURATION_UPDATE
    })
    public Response updateCsafAggregator(UUID id, UpdateCsafAggregatorRequest request) {
        final CsafAggregator updatedAggregator = inJdbiTransaction(getAlpineRequest(), handle -> {
            final var dao = handle.attach(CsafAggregatorDao.class);

            final CsafAggregator aggregator = dao.getById(id, /* forUpdate */ true);
            if (aggregator == null) {
                throw new NotFoundException();
            }

            boolean modified = false;
            if (aggregator.isEnabled() != request.getEnabled()) {
                aggregator.setEnabled(request.getEnabled());
                modified = true;
            }

            if (!modified) {
                return null;
            }

            return dao.update(aggregator);
        });

        if (updatedAggregator == null) {
            return Response.notModified().build();
        }

        LOGGER.info(
                SecurityMarkers.SECURITY_AUDIT,
                "Updated CSAF aggregator '{}'",
                updatedAggregator.getNamespace());
        return Response.ok(convert(updatedAggregator)).build();
    }

    @Override
    @PermissionRequired({
            Permissions.Constants.SYSTEM_CONFIGURATION,
            Permissions.Constants.SYSTEM_CONFIGURATION_DELETE
    })
    public Response deleteCsafAggregator(UUID id) {
        final CsafAggregator aggregator = inJdbiTransaction(
                getAlpineRequest(),
                handle -> handle.attach(CsafAggregatorDao.class).deleteById(id));

        if (aggregator != null) {
            LOGGER.info(
                    SecurityMarkers.SECURITY_AUDIT,
                    "Deleted CSAF aggregator '{}'",
                    aggregator.getNamespace());
        }

        return Response.noContent().build();
    }

    @Override
    @PermissionRequired({
            Permissions.Constants.SYSTEM_CONFIGURATION,
            Permissions.Constants.SYSTEM_CONFIGURATION_READ
    })
    public Response listCsafAggregators(String searchText, String pageToken, Integer limit) {
        final Page<CsafAggregator> aggregatorsPage = withJdbiHandle(
                getAlpineRequest(),
                handle -> handle.attach(CsafAggregatorDao.class).list(
                        new ListCsafAggregatorsQuery()
                                .withSearchText(searchText)
                                .withPageToken(pageToken)
                                .withLimit(limit)));

        final var responseItems = aggregatorsPage.items().stream()
                .map(this::convert)
                .toList();

        final var response = ListCsafAggregatorsResponse.builder()
                .items(responseItems)
                .nextPageToken(aggregatorsPage.nextPageToken())
                .total(convertTotalCount(aggregatorsPage.totalCount()))
                .build();

        return Response.ok(response).build();
    }

    @Override
    @PermissionRequired({
            Permissions.Constants.SYSTEM_CONFIGURATION,
            Permissions.Constants.SYSTEM_CONFIGURATION_UPDATE
    })
    public Response triggerCsafProviderDiscovery(UUID id) {
        final CsafAggregator aggregator = withJdbiHandle(
                getAlpineRequest(),
                handle -> handle.attach(CsafAggregatorDao.class).getById(id));
        if (aggregator == null) {
            throw new NotFoundException();
        }

        if (!aggregator.isEnabled()) {
            throw new BadRequestException();
        }

        final UUID runId = dexEngine.createRun(
                new CreateWorkflowRunRequest<>(DiscoverCsafProvidersWorkflow.class)
                        .withWorkflowInstanceId("discover-csaf-providers:" + aggregator.getId())
                        .withArgument(DiscoverCsafProvidersArg.newBuilder()
                                .setAggregatorId(aggregator.getId().toString())
                                .build()));
        if (runId == null) {
            throw new AlreadyExistsException("Discovery is already in progress");
        }

        LOGGER.info(
                SecurityMarkers.SECURITY_AUDIT,
                "Triggered provider discovery for CSAF aggregator '{}'",
                aggregator.getNamespace());
        return Response.accepted().build();
    }

    @Override
    @PermissionRequired({
            Permissions.Constants.SYSTEM_CONFIGURATION,
            Permissions.Constants.SYSTEM_CONFIGURATION_CREATE
    })
    public Response createCsafProvider(CreateCsafProviderRequest request) {
        final var provider = new CsafProvider(
                request.getUrl(),
                request.getNamespace(),
                request.getName());
        provider.setEnabled(request.getEnabled());

        final CsafProvider createdProvider = inJdbiTransaction(
                getAlpineRequest(),
                handle -> handle.attach(CsafProviderDao.class).create(provider));
        if (createdProvider == null) {
            throw new AlreadyExistsException("", null);
        }

        LOGGER.info(
                SecurityMarkers.SECURITY_AUDIT,
                "Created CSAF provider '{}'",
                createdProvider.getNamespace());

        return Response
                .created(
                        getUriInfo().getBaseUriBuilder()
                                .path("/csaf-providers")
                                .path(createdProvider.getId().toString())
                                .build())
                .entity(convert(provider))
                .build();
    }

    @Override
    @PermissionRequired({
            Permissions.Constants.SYSTEM_CONFIGURATION,
            Permissions.Constants.SYSTEM_CONFIGURATION_READ
    })
    public Response getCsafProvider(UUID id) {
        final CsafProvider provider = withJdbiHandle(
                getAlpineRequest(),
                handle -> handle.attach(CsafProviderDao.class).getById(id));
        if (provider == null) {
            throw new NotFoundException();
        }

        return Response.ok(convert(provider)).build();
    }

    @Override
    @PermissionRequired({
            Permissions.Constants.SYSTEM_CONFIGURATION,
            Permissions.Constants.SYSTEM_CONFIGURATION_UPDATE
    })
    public Response updateCsafProvider(UUID id, UpdateCsafProviderRequest request) {
        final CsafProvider updatedProvider = inJdbiTransaction(getAlpineRequest(), handle -> {
            final var dao = handle.attach(CsafProviderDao.class);

            final CsafProvider provider = dao.getById(id, /* forUpdate */ true);
            if (provider == null) {
                throw new NotFoundException();
            }

            boolean modified = false;
            if (provider.isEnabled() != request.getEnabled()) {
                provider.setEnabled(request.getEnabled());
                modified = true;
            }

            if (!modified) {
                return null;
            }

            return dao.update(provider);
        });

        if (updatedProvider == null) {
            return Response.notModified().build();
        }

        LOGGER.info(
                SecurityMarkers.SECURITY_AUDIT,
                "Updated CSAF provider '{}'",
                updatedProvider.getNamespace());
        return Response.ok(convert(updatedProvider)).build();
    }

    @Override
    @PermissionRequired({
            Permissions.Constants.SYSTEM_CONFIGURATION,
            Permissions.Constants.SYSTEM_CONFIGURATION_DELETE
    })
    public Response deleteCsafProvider(UUID id) {
        final CsafProvider provider = inJdbiTransaction(
                getAlpineRequest(),
                handle -> handle.attach(CsafProviderDao.class).deleteById(id));

        if (provider != null) {
            LOGGER.info(
                    SecurityMarkers.SECURITY_AUDIT,
                    "Deleted CSAF provider '{}'",
                    provider.getNamespace());
        }

        return Response.noContent().build();
    }

    @Override
    @PermissionRequired({
            Permissions.Constants.SYSTEM_CONFIGURATION,
            Permissions.Constants.SYSTEM_CONFIGURATION_READ
    })
    public Response listCsafProviders(
            Boolean discovered,
            String searchText,
            String pageToken,
            Integer limit) {
        final Page<CsafProvider> sourcesPage = withJdbiHandle(
                getAlpineRequest(),
                handle -> handle.attach(CsafProviderDao.class).list(
                        new ListCsafProvidersQuery()
                                .withDiscovered(discovered)
                                .withSearchText(searchText)
                                .withPageToken(pageToken)
                                .withLimit(limit)));

        final var responseItems = sourcesPage.items().stream()
                .map(this::convert)
                .toList();

        final var response = ListCsafProvidersResponse.builder()
                .items(responseItems)
                .nextPageToken(sourcesPage.nextPageToken())
                .total(convertTotalCount(sourcesPage.totalCount()))
                .build();

        return Response.ok(response).build();
    }

    private org.dependencytrack.api.v2.model.CsafAggregator convert(CsafAggregator aggregator) {
        return org.dependencytrack.api.v2.model.CsafAggregator.builder()
                .id(aggregator.getId())
                .namespace(aggregator.getNamespace())
                .name(aggregator.getName())
                .url(aggregator.getUrl())
                .enabled(aggregator.isEnabled())
                .lastDiscoveryAt(aggregator.getLastDiscoveryAt() != null
                        ? aggregator.getLastDiscoveryAt().toEpochMilli()
                        : null)
                .createdAt(aggregator.getCreatedAt().toEpochMilli())
                .updatedAt(aggregator.getUpdatedAt() != null
                        ? aggregator.getUpdatedAt().toEpochMilli()
                        : null)
                .build();
    }

    private org.dependencytrack.api.v2.model.CsafProvider convert(CsafProvider provider) {
        return org.dependencytrack.api.v2.model.CsafProvider.builder()
                .id(provider.getId())
                .namespace(provider.getNamespace())
                .name(provider.getName())
                .url(provider.getUrl())
                .enabled(provider.isEnabled())
                .discoveredFrom(provider.getDiscoveredFrom())
                .discoveredAt(provider.getDiscoveredAt() != null
                        ? provider.getDiscoveredAt().toEpochMilli()
                        : null)
                .latestDocumentReleaseDate(provider.getLatestDocumentReleaseDate() != null
                        ? provider.getLatestDocumentReleaseDate().toEpochMilli()
                        : null)
                .createdAt(provider.getCreatedAt().toEpochMilli())
                .updatedAt(provider.getUpdatedAt() != null
                        ? provider.getUpdatedAt().toEpochMilli()
                        : null)
                .build();
    }

}
