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
package alpine.test.config;

import org.eclipse.microprofile.config.ConfigProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ConfigPropertyExtensionTest {

    @RegisterExtension
    static ConfigPropertyExtension extension = new ConfigPropertyExtension()
            .withProperty("foo.bar", "baz")
            .withProperty("oof.rab", "${foo.bar}");

    @Test
    @WithConfigProperty(value = {
            "local.foo.bar=local-baz",
            "lacol.oof.rab=${local.foo.bar}"})
    void test() {
        assertEquals("baz", ConfigProvider.getConfig().getValue("foo.bar", String.class));
        assertEquals("baz", ConfigProvider.getConfig().getValue("oof.rab", String.class));
        assertEquals("local-baz", ConfigProvider.getConfig().getValue("local.foo.bar", String.class));
        assertEquals("local-baz", ConfigProvider.getConfig().getValue("lacol.oof.rab", String.class));
    }

}
