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
package org.dependencytrack.csaf;

import io.csaf.retrieval.RetrievedDocument;
import io.csaf.schema.generated.Csaf;
import kotlinx.serialization.json.Json;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.persistence.jdbi.AdvisoryDao;
import org.dependencytrack.persistence.jdbi.AdvisoryDao.AdvisoryDetailRow;
import org.jdbi.v3.core.Handle;
import org.junit.Test;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.stream.Stream;

import static org.apache.commons.io.IOUtils.resourceToString;
import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.openJdbiHandle;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

public class CsafDocumentImportTaskTest extends PersistenceCapableTest {

    private Handle jdbiHandle;
    private AdvisoryDao advisoryDao;
    private CsafProviderDao providerDao;

    @Override
    public void before() throws Exception {
        super.before();

        jdbiHandle = openJdbiHandle();
        advisoryDao = jdbiHandle.attach(AdvisoryDao.class);
        providerDao = jdbiHandle.attach(CsafProviderDao.class);
    }

    @Override
    public void after() {
        if (jdbiHandle != null) {
            jdbiHandle.close();
        }

        super.after();
    }

    @Test
    public void shouldImportDocumentsAsAdvisories() throws Exception {
        var provider = new CsafProvider(
                URI.create("https://wid.cert-bund.de/.well-known/csaf/provider-metadata.json"),
                URI.create("https://www.bsi.bund.de/"),
                "Bundesamt für Sicherheit in der Informationstechnik");
        provider.setEnabled(true);
        providerDao.create(provider);

        final var clientMock = mock(CsafClient.class);
        doReturn(Stream.of(createDocument())).when(clientMock).getDocuments(eq(provider), any());

        final var task = new CsafDocumentImportTask(clientMock);
        task.inform(new CsafDocumentImportEvent());

        final List<AdvisoryDetailRow> advisories = advisoryDao.getAllAdvisories(null, null);
        assertThat(advisories).satisfiesExactly(advisory -> {
            assertThat(advisory.publisher()).isEqualTo("https://csaf.io");
            assertThat(advisory.name()).isEqualTo("OASIS_CSAF_TC-CSAF_2.0-2021-6-1-04-11");
            assertThat(advisory.title()).isEqualTo("Mandatory test: Missing Definition of Product Group ID (valid example 1)");
            assertThat(advisory.version()).isEqualTo("1");
            assertThat(advisory.format()).isEqualTo("CSAF");
            assertThat(advisory.url()).isEqualTo("https://example.com/csaf/advisory.json");
            assertThat(advisory.lastFetched()).isNotNull();
            assertThat(advisory.seen()).isFalse();
        });

        final List<Vulnerability> vulns = qm.getVulnerabilities().getList(Vulnerability.class);
        assertThat(vulns).isEmpty();

        provider = providerDao.getById(provider.getId());
        assertThat(provider).isNotNull();
        assertThat(provider.getLatestDocumentReleaseDate()).isNotNull();
    }

    private RetrievedDocument createDocument() throws Exception {
        final String csafJson = resourceToString(
                "/csaf/oasis_csaf_tc-csaf_2_0-2021-6-1-04-11.json",
                StandardCharsets.UTF_8);

        final Csaf csaf = Json.Default.decodeFromString(
                Csaf.Companion.serializer(),
                csafJson);

        return new RetrievedDocument(csaf, "https://example.com/csaf/advisory.json");
    }


}