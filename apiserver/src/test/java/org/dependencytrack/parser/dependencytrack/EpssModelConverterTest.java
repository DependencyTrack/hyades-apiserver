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
package org.dependencytrack.parser.dependencytrack;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Epss;
import org.dependencytrack.proto.mirror.v1.EpssItem;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class EpssModelConverterTest extends PersistenceCapableTest {

    @Test
    public void testConvert() {
        final var epssItemInput = EpssItem.newBuilder().setCve("CVE-111")
                .setEpss(2.2).setPercentile(3.3).build();
        final Epss epssConverted = EpssModelConverter.convert(epssItemInput);
        assertThat(epssConverted.getCve()).isEqualTo("CVE-111");
        assertThat(epssConverted.getScore()).isEqualByComparingTo("2.2");
        assertThat(epssConverted.getPercentile()).isEqualByComparingTo("3.3");
    }
}
