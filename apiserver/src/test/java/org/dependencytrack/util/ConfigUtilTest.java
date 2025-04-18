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

import alpine.Config;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.EnvironmentVariables;
import org.junit.contrib.java.lang.system.RestoreSystemProperties;

import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@Ignore // Dirties the JVM which doesn't play nicely with Maven Surefire reusing a JVM for all tests.
public class ConfigUtilTest {

    @Rule
    public final RestoreSystemProperties restoreSystemProperties = new RestoreSystemProperties();

    @Rule
    public final EnvironmentVariables environmentVariables = new EnvironmentVariables();

    private static Method configInitMethod;
    private static Method configResetMethod;

    @BeforeClass
    public static void setUpClass() throws Exception {
        configInitMethod = Config.class.getDeclaredMethod("init");
        configInitMethod.setAccessible(true);

        configResetMethod = Config.class.getDeclaredMethod("reset");
        configResetMethod.setAccessible(true);
    }

    @After
    public void tearDown() throws Exception {
        configResetMethod.invoke(null);
    }

    @AfterClass
    public static void tearDownClass() throws Exception {
        configInitMethod.invoke(Config.getInstance()); // Ensure we're not affecting other tests
    }

    @Test
    public void testGetPassThroughPropertiesEmpty() throws Exception {
        configInitMethod.invoke(Config.getInstance());

        assertThat(Config.getInstance().getPassThroughProperties("some.prefix")).isEmpty();
    }

    @Test
    public void testGetPassThroughProperties() throws Exception {
        final Path propertiesPath = Files.createTempFile(null, ".properties");
        Files.writeString(propertiesPath, """
                foo=fromProps1
                some.prefix=fromProps2
                some.prefix.foo=fromProps3
                some.prefix.foo.bar=fromProps4
                some.pre.fix.foo=fromProps5
                prefix.foo=fromProps6
                some.prefix.from.props=fromProps7
                SOME.PREFIX.FROM.PROPS.UPPERCASE=fromProps8
                Some.Prefix.From.Props.MixedCase=fromProps9
                """);

        System.setProperty("alpine.application.properties", propertiesPath.toString());

        configInitMethod.invoke(Config.getInstance());

        environmentVariables.set("FOO", "fromEnv1");
        environmentVariables.set("SOME_PREFIX", "fromEnv2");
        environmentVariables.set("SOME_PREFIX_FOO", "fromEnv3");
        environmentVariables.set("SOME_PREFIX_FOO_BAR", "fromEnv4");
        environmentVariables.set("SOME_PRE_FIX_FOO", "fromEnv5");
        environmentVariables.set("PREFIX_FOO", "fromEnv6");
        environmentVariables.set("SOME_PREFIX_FROM_ENV", "fromEnv7");
        environmentVariables.set("some_prefix_from_env_lowercase", "fromEnv8");
        environmentVariables.set("Some_Prefix_From_Env_MixedCase", "fromEnv9");

        assertThat(ConfigUtil.getPassThroughProperties(Config.getInstance(), "some.prefix"))
                .containsExactlyInAnyOrderEntriesOf(Map.of(
                        "some.prefix.foo", "fromEnv3", // ENV takes precedence over properties
                        "some.prefix.foo.bar", "fromEnv4", // ENV takes precedence over properties
                        "some.prefix.from.env", "fromEnv7",
                        "some.prefix.from.props", "fromProps7"
                ));
    }

}