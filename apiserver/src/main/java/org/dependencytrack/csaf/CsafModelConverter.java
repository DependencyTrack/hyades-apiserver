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
import org.dependencytrack.model.Advisory;

/**
 * @since 5.7.0
 */
public final class CsafModelConverter {

    private CsafModelConverter() {
    }

    public static Advisory convert(RetrievedDocument retrievedDoc) {
        final Csaf csaf = retrievedDoc.getJson();
        final Csaf.Document csafDoc = csaf.getDocument();

        final var advisory = new Advisory();
        advisory.setTitle(csafDoc.getTitle());
        advisory.setLastFetched(csafDoc.getTracking().getCurrent_release_date().getValue$kotlinx_datetime());
        advisory.setContent(Json.Default.encodeToString(Csaf.Companion.serializer(), csaf));
        advisory.setName(csafDoc.getTracking().getId());
        advisory.setVersion(csafDoc.getTracking().getVersion());
        advisory.setPublisher(csafDoc.getPublisher().getNamespace().toString());
        advisory.setUrl(retrievedDoc.getUrl());
        advisory.setFormat("CSAF");

        // TODO: Convert vulnerabilities. But consider the following:
        //   * CSAF vulns are not required to have a unique identifier.
        //       * They *can* have a CVE
        //       * They *can* have one or more other IDs
        //   * If a CSAF vuln has a CVE, we should reuse an existing Vulnerability
        //     record if one exists for that CVE.
        //   * If a CSAF vuln does not have a CVE, we need to deterministically
        //     create an ID. This should consider that the same vulnerability can
        //     appear across multiple advisories. We should avoid creating too many
        //     records if possible, since every record more creates noise.

        return advisory;
    }

}
