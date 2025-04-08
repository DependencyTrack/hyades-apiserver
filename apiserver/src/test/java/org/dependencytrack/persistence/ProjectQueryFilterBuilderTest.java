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

import org.junit.Test;

import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class ProjectQueryFilterBuilderTest {

    @Test
    public void testEmptyBuilderBuildsEmptyFilter() {
        var builder = new ProjectQueryFilterBuilder();
        var filter = builder.buildFilter();
        assertNotNull(filter);
        assertTrue(filter.isEmpty());
    }

    @Test
    public void testEmptyBuilderBuildsEmptyParams() {
        var builder = new ProjectQueryFilterBuilder();
        var params = builder.getParams();
        assertNotNull(params);
        assertTrue(params.isEmpty());
    }

    @Test
    public void testBuilderBuildsFilterAndParams() {
        var testName = "test";
        var builder = new ProjectQueryFilterBuilder().withName(testName);
        assertEquals(Map.of("name", testName), builder.getParams());
        assertEquals("(name == :name)", builder.buildFilter());
    }

}
