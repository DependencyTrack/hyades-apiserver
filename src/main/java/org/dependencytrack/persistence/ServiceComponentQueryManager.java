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
package org.dependencytrack.persistence;

import alpine.persistence.PaginatedResult;
import alpine.resources.AlpineRequest;
import org.dependencytrack.model.ComponentIdentity;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ServiceComponent;
import org.dependencytrack.resources.v1.vo.DependencyGraphResponse;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import java.util.List;
import java.util.UUID;

final class ServiceComponentQueryManager extends QueryManager implements IQueryManager {

    /**
     * Constructs a new QueryManager.
     * @param pm a PersistenceManager object
     */
    ServiceComponentQueryManager(final PersistenceManager pm) {
        super(pm);
    }

    /**
     * Constructs a new QueryManager.
     * @param pm a PersistenceManager object
     * @param request an AlpineRequest object
     */
    ServiceComponentQueryManager(final PersistenceManager pm, final AlpineRequest request) {
        super(pm, request);
    }

    /**
     * Returns a service component by matching its identity information.
     * @param project the Project the component is a dependency of
     * @param cid the identity values of the component
     * @return a ServiceComponent object, or null if not found
     */
    public ServiceComponent matchServiceIdentity(final Project project, final ComponentIdentity cid) {
        final Query<ServiceComponent> query = pm.newQuery(ServiceComponent.class, "project == :project && group == :group && name == :name && version == :version");
        query.setRange(0, 1);
        return singleResult(query.executeWithArray(project, cid.getGroup(), cid.getName(), cid.getVersion()));
    }

    /**
     * Creates a new ServiceComponent.
     * @param service the ServiceComponent to persist
     * @param commitIndex specifies if the search index should be committed (an expensive operation)
     * @return a new ServiceComponent
     */
    public ServiceComponent createServiceComponent(ServiceComponent service, boolean commitIndex) {
        final ServiceComponent result = persist(service);
        return result;
    }

    /**
     * Returns a List of all ServiceComponent for the specified Project.
     * This method if designed NOT to provide paginated results.
     * @param project the Project to retrieve dependencies of
     * @return a List of ServiceComponent objects
     */
    @SuppressWarnings("unchecked")
    public List<ServiceComponent> getAllServiceComponents(Project project) {
        final Query<ServiceComponent> query = pm.newQuery(ServiceComponent.class, "project == :project");
        query.getFetchPlan().setMaxFetchDepth(2);
        query.setOrdering("name asc");
        return (List<ServiceComponent>)query.execute(project);
    }

    /**
     * Returns a List of ServiceComponents for the specified Project.
     * @param project the Project to retrieve dependencies of
     * @return a List of ServiceComponent objects
     */
    public PaginatedResult getServiceComponents(final Project project, final boolean includeMetrics) {
        final PaginatedResult result;
        final Query<ServiceComponent> query = pm.newQuery(ServiceComponent.class, "project == :project");
        query.getFetchPlan().setMaxFetchDepth(2);
        if (orderBy == null) {
            query.setOrdering("name asc, version desc");
        }
        if (filter != null) {
            query.setFilter("project == :project && name.toLowerCase().matches(:name)");
            final String filterString = ".*" + filter.toLowerCase() + ".*";
            result = execute(query, project, filterString);
        } else {
            result = execute(query, project);
        }
        if (includeMetrics) {
            // TODO
        }
        return result;
    }

    public ServiceComponent cloneServiceComponent(ServiceComponent sourceService, Project destinationProject, boolean commitIndex) {
        final ServiceComponent service = new ServiceComponent();
        service.setProvider(sourceService.getProvider());
        service.setGroup(sourceService.getGroup());
        service.setName(sourceService.getName());
        service.setVersion(sourceService.getVersion());
        service.setDescription(sourceService.getDescription());
        service.setEndpoints(sourceService.getEndpoints());
        service.setAuthenticated(sourceService.getAuthenticated());
        service.setCrossesTrustBoundary(sourceService.getCrossesTrustBoundary());
        service.setData(sourceService.getData());
        service.setExternalReferences(sourceService.getExternalReferences());
        // TODO Add support for parent component and children components
        service.setNotes(sourceService.getNotes());
        service.setVulnerabilities(sourceService.getVulnerabilities());
        service.setProject(destinationProject);
        return createServiceComponent(service, commitIndex);
    }

    /**
     * Updated an existing ServiceComponent.
     * @param transientServiceComponent the service to update
     * @param commitIndex specifies if the search index should be committed (an expensive operation)
     * @return a Component
     */
    public ServiceComponent updateServiceComponent(ServiceComponent transientServiceComponent, boolean commitIndex) {
        final ServiceComponent service = getObjectByUuid(ServiceComponent.class, transientServiceComponent.getUuid());
        service.setName(transientServiceComponent.getName());
        service.setVersion(transientServiceComponent.getVersion());
        service.setGroup(transientServiceComponent.getGroup());
        service.setDescription(transientServiceComponent.getDescription());
        final ServiceComponent result = persist(service);
        return result;
    }

    /**
     * Returns a list of all {@link DependencyGraphResponse} objects by {@link ServiceComponent} UUID.
     * @param uuids a list of {@link ServiceComponent} UUIDs
     * @return a list of {@link DependencyGraphResponse} objects
     * @since 4.9.0
     */
    public List<DependencyGraphResponse> getDependencyGraphByUUID(final List<UUID> uuids) {
        final Query<ServiceComponent> query = this.getObjectsByUuidsQuery(ServiceComponent.class, uuids);
        query.setResult("uuid, name, version, null, null, null");
        return List.copyOf(query.executeResultList(DependencyGraphResponse.class));
    }
}
