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
package org.dependencytrack.dex.engine.api.request;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ListWorkflowSchedulesRequestTest {

    @Test
    void shouldPopulateFieldsUsingWithers() {
        final var request = new ListWorkflowSchedulesRequest()
                .withWorkflowName("workflowName")
                .withPageToken("pageToken")
                .withLimit(666);

        assertThat(request.workflowName()).isEqualTo("workflowName");
        assertThat(request.pageToken()).isEqualTo("pageToken");
        assertThat(request.limit()).isEqualTo(666);
    }

}