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

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

public class CollectionIntegerConverterTest {

    @Test
    public void convertToDatastoreTest() {
        assertThat(new CollectionIntegerConverter().convertToDatastore(null)).isNull();
        assertThat(new CollectionIntegerConverter().convertToDatastore(List.of())).isEmpty();
        assertThat(new CollectionIntegerConverter().convertToDatastore(List.of(666))).isEqualTo("666");
        assertThat(new CollectionIntegerConverter().convertToDatastore(List.of(666, 123))).isEqualTo("666,123");
    }

    @Test
    public void convertToAttributeTest() {
        assertThat(new CollectionIntegerConverter().convertToAttribute(null)).isNull();
        assertThat(new CollectionIntegerConverter().convertToAttribute("")).isNull();
        assertThat(new CollectionIntegerConverter().convertToAttribute(" ")).isNull();
        assertThat(new CollectionIntegerConverter().convertToAttribute("666")).containsOnly(666);
        assertThat(new CollectionIntegerConverter().convertToAttribute("666,123")).containsOnly(666, 123);
        assertThat(new CollectionIntegerConverter().convertToAttribute("666,, ,123")).containsOnly(666, 123);
    }

}