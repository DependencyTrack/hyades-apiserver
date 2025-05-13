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
package org.dependencytrack.util;

import alpine.test.config.ConfigPropertyRule;
import alpine.test.config.WithConfigProperty;
import org.junit.Rule;
import org.junit.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

public class ConfigUtilTest {

    @Rule
    public final ConfigPropertyRule configPropertyRule = new ConfigPropertyRule();

    @Test
    public void testGetPassThroughPropertiesEmpty() {
        assertThat(ConfigUtil.getPassThroughProperties("some.prefix")).isEmpty();
    }

    @Test
    @WithConfigProperty(value = {
            "some=1",
            "some.prefix=2",
            "some.prefix.foo=3",
            "some.prefix.foo.bar=4"
    })
    public void testGetPassThroughProperties() {
        assertThat(ConfigUtil.getPassThroughProperties("some.prefix"))
                .containsExactlyInAnyOrderEntriesOf(Map.of(
                        "some.prefix.foo", "3",
                        "some.prefix.foo.bar", "4"
                ));
    }

}