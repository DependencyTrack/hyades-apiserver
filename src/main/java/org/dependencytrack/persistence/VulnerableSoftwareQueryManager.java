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
import com.github.packageurl.PackageURL;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.model.Cwe;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerableSoftware;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import java.util.ArrayList;
import java.util.List;

final class VulnerableSoftwareQueryManager extends QueryManager implements IQueryManager {

    /**
     * Constructs a new QueryManager.
     * @param pm a PersistenceManager object
     */
    VulnerableSoftwareQueryManager(final PersistenceManager pm) {
        super(pm);
    }

    /**
     * Constructs a new QueryManager.
     * @param pm a PersistenceManager object
     * @param request an AlpineRequest object
     */
    VulnerableSoftwareQueryManager(final PersistenceManager pm, final AlpineRequest request) {
        super(pm, request);
    }

    /**
     * Returns a VulnerableSoftware by it's CPE v2.3 string.
     * @param cpe23 the CPE 2.3 string
     * @return a VulnerableSoftware object, or null if not found
     */
    public VulnerableSoftware getVulnerableSoftwareByCpe23(String cpe23,
                                                           String versionEndExcluding, String versionEndIncluding,
                                                           String versionStartExcluding, String versionStartIncluding) {
        final Query<VulnerableSoftware> query = pm.newQuery(VulnerableSoftware.class);
        query.setFilter("cpe23 == :cpe23 && versionEndExcluding == :versionEndExcluding && versionEndIncluding == :versionEndIncluding && versionStartExcluding == :versionStartExcluding && versionStartIncluding == :versionStartIncluding");
        query.setRange(0, 1);
        return singleResult(query.executeWithArray(cpe23, versionEndExcluding, versionEndIncluding, versionStartExcluding, versionStartIncluding));
    }

    /**
     * Returns a VulnerableSoftware by it's CPE v2.3 string and the affected version.
     * @param cpe23 the CPE 2.3 string
     * @return a VulnerableSoftware object, or null if not found
     */
    public VulnerableSoftware getVulnerableSoftwareByCpe23AndVersion(String cpe23, String version) {
        final Query<VulnerableSoftware> query = pm.newQuery(VulnerableSoftware.class);
        query.setFilter("cpe23 == :cpe23 && version == :version");
        query.setRange(0, 1);
        return singleResult(query.executeWithArray(cpe23, version));
    }

    /**
     * Returns a List of all VulnerableSoftware objects.
     * @return a List of all VulnerableSoftware objects
     */
    public PaginatedResult getVulnerableSoftware() {
        final Query<VulnerableSoftware> query = pm.newQuery(VulnerableSoftware.class);
        if (orderBy == null) {
            query.setOrdering("id asc");
        }
        if (filter != null) {
            query.setFilter("vendor.toLowerCase().matches(:filter) || product.toLowerCase().matches(:filter)");
            final String filterString = ".*" + filter.toLowerCase() + ".*";
            return execute(query, filterString);
        }
        return execute(query);
    }

    /**
     * Returns a List of all VulnerableSoftware objects that match the specified CPE (v2.2 or v2.3) uri.
     * @return a List of matching VulnerableSoftware objects
     */
    @SuppressWarnings("unchecked")
    public List<VulnerableSoftware> getAllVulnerableSoftwareByCpe(final String cpeString) {
        final Query<VulnerableSoftware> query = pm.newQuery(VulnerableSoftware.class, "cpe23 == :cpeString || cpe22 == :cpeString");
        return (List<VulnerableSoftware>)query.execute(cpeString);
    }

    /**
     * Returns a List of all VulnerableSoftware objects that match the specified PackageURL
     * @return a List of matching VulnerableSoftware objects
     */
    @SuppressWarnings("unchecked")
    public VulnerableSoftware getVulnerableSoftwareByPurl(String purlType, String purlNamespace, String purlName,
                                                                   String versionEndExcluding, String versionEndIncluding,
                                                                   String versionStartExcluding, String versionStartIncluding) {
        final Query<VulnerableSoftware> query = pm.newQuery(VulnerableSoftware.class, "purlType == :purlType && purlNamespace == :purlNamespace && purlName == :purlName && versionEndExcluding == :versionEndExcluding && versionEndIncluding == :versionEndIncluding && versionStartExcluding == :versionStartExcluding && versionStartIncluding == :versionStartIncluding");
        query.setRange(0, 1);
        return singleResult(query.executeWithArray(purlType, purlNamespace, purlName, versionEndExcluding, versionEndIncluding, versionStartExcluding, versionStartIncluding));
    }

    /**
     * Fetch all {@link VulnerableSoftware} instances associated with a given {@link Vulnerability}.
     *
     * @param source The source of the vulnerability
     * @param vulnId The ID of the vulnerability
     * @return a {@link List} of {@link VulnerableSoftware}s
     */
    @Override
    @SuppressWarnings("unchecked")
    public List<VulnerableSoftware> getVulnerableSoftwareByVulnId(final String source, final String vulnId) {
        final Query<?> query = pm.newQuery(Query.JDOQL, """
                SELECT FROM org.dependencytrack.model.VulnerableSoftware
                WHERE vulnerabilities.contains(vuln)
                    && vuln.source == :source && vuln.vulnId == :vulnId
                VARIABLES org.dependencytrack.model.Vulnerability vuln
                """);
        query.setParameters(source, vulnId);
        return (List<VulnerableSoftware>) query.executeList();
    }

    /**
     * Returns a List of all VulnerableSoftware objects that match the specified PackageURL
     * @return a List of matching VulnerableSoftware objects
     */
    @SuppressWarnings("unchecked")
    public List<VulnerableSoftware> getAllVulnerableSoftwareByPurl(final PackageURL purl) {
        final Query<VulnerableSoftware> query = pm.newQuery(VulnerableSoftware.class, "(purlType == :purlType && purlNamespace == :purlNamespace && purlName == :purlName && purlVersion == :purlVersion)");
        return (List<VulnerableSoftware>)query.executeWithArray(purl.getType(), purl.getNamespace(), purl.getName(), purl.getVersion());
    }

    /**
     * Returns a VulnerableSoftware object that match the specified PackageURL and the affected version
     * @return matching VulnerableSoftware object
     */
    public VulnerableSoftware getVulnerableSoftwareByPurlAndVersion(String purlType, String purlNamespace, String purlName, String version) {
        final Query<VulnerableSoftware> query = pm.newQuery(VulnerableSoftware.class, "purlType == :purlType && purlNamespace == :purlNamespace && purlName == :purlName && version == :version");
        query.setRange(0, 1);
        return singleResult(query.executeWithArray(purlType, purlNamespace, purlName, version));

    }

    /**
     * Returns a List of all VulnerableSoftware objects that match the specified vendor/product/version.
     * @return a List of matching VulnerableSoftware objects
     */
    @SuppressWarnings("unchecked")
    public List<VulnerableSoftware> getAllVulnerableSoftware(final String cpePart, final String cpeVendor, final String cpeProduct, final String cpeVersion, final PackageURL purl) {
        final Query<VulnerableSoftware> query = pm.newQuery(VulnerableSoftware.class);
        query.setFilter("(part == :part && vendor == :vendor && product == :product && version == :version) || (purlType == :purlType && purlNamespace == :purlNamespace && purlName == :purlName && purlVersion == :purlVersion)");
        return (List<VulnerableSoftware>)query.executeWithArray(cpePart, cpeVendor, cpeProduct, cpeVersion, purl.getType(), purl.getNamespace(), purl.getName(), purl.getVersion());
    }

    /**
     * Returns a List of all VulnerableSoftware objects that match the specified vendor/product.
     * @return a List of matching VulnerableSoftware objects
     */
    @SuppressWarnings("unchecked")
    public List<VulnerableSoftware> getAllVulnerableSoftware(final String part, final String vendor, final String product, final PackageURL purl) {
        final Query<VulnerableSoftware> query = pm.newQuery(VulnerableSoftware.class);
        String filter = "";
        boolean cpeSpecified = (part != null && vendor != null && product != null);
        if (cpeSpecified) {
            filter += "(part == :part && vendor == :vendor && product == :product)";
        }
        if (cpeSpecified && purl != null) {
            filter += " || ";
        }
        if (purl != null) {
            filter += "(purlType == :purlType && purlNamespace == :purlNamespace && purlName == :purlName)";
        }
        query.setFilter(filter);
        if (cpeSpecified && purl != null) {
            return (List<VulnerableSoftware>)query.executeWithArray(part, vendor, product, purl.getType(), purl.getNamespace(), purl.getName());
        } else if (cpeSpecified) {
            return (List<VulnerableSoftware>)query.executeWithArray(part, vendor, product);
        } else if (purl != null) {
            return (List<VulnerableSoftware>)query.executeWithArray(purl.getType(), purl.getNamespace(), purl.getName());
        } else {
            return new ArrayList<>();
        }
    }

    /**
     * Checks if the specified CWE id exists or not. If not, creates
     * a new CWE with the specified ID and name. In both cases, the
     * CWE will be returned.
     * @param id the CWE ID
     * @param name the name of the CWE
     * @return a CWE object
     */
    public Cwe createCweIfNotExist(int id, String name) {
        Cwe cwe = getCweById(id);
        if (cwe != null) {
            return cwe;
        }
        cwe = new Cwe();
        cwe.setCweId(id);
        cwe.setName(name);
        return persist(cwe);
    }

    /**
     * Returns a CWE by it's CWE-ID.
     * @param cweId the CWE-ID
     * @return a CWE object, or null if not found
     */
    public Cwe getCweById(int cweId) {
        final Query<Cwe> query = pm.newQuery(Cwe.class, "cweId == :cweId");
        query.setRange(0, 1);
        return singleResult(query.execute(cweId));
    }

    /**
     * Returns a complete list of all CWE's.
     * @return a List of CWEs
     */
    public PaginatedResult getCwes() {
        final Query<Cwe> query = pm.newQuery(Cwe.class);
        if (orderBy == null) {
            query.setOrdering("id asc");
        }
        if (filter != null) {
            if (StringUtils.isNumeric(filter)) {
                query.setFilter("cweId == :cweId || name.matches(:filter)");
                final String filterString = ".*" + filter.toLowerCase() + ".*";
                return execute(query, Integer.valueOf(filter), filterString);
            } else {
                query.setFilter("name.toLowerCase().matches(:filter)");
                final String filterString = ".*" + filter.toLowerCase() + ".*";
                return execute(query, filterString);
            }
        }
        return execute(query);
    }

    /**
     * Returns a complete list of all CWE's.
     * @return a List of CWEs
     */
    public List<Cwe> getAllCwes() {
        final Query<Cwe> query = pm.newQuery(Cwe.class);
        query.setOrdering("id asc");
        return query.executeList();
    }
}
