/*
 * This file is part of Alpine.
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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package alpine.common.util;

import org.dependencytrack.support.config.source.memory.MemoryConfigSource;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junitpioneer.jupiter.RestoreEnvironmentVariables;
import org.junitpioneer.jupiter.SetEnvironmentVariable;

class ThreadUtilTest {

    @AfterEach
    void afterEach() {
        MemoryConfigSource.clear();
    }

    @Test
    void determineNumberOfWorkerThreadsStaticTest() {
        MemoryConfigSource.setProperty("alpine.worker.threads", "10");

        Assertions.assertEquals(10, ThreadUtil.determineNumberOfWorkerThreads());
    }

    @Test
    @RestoreEnvironmentVariables
    @SetEnvironmentVariable(key = "ALPINE_WORKER_THREADS", value = "0")
    void determineNumberOfWorkerThreadsDynamicTest() {
        MemoryConfigSource.setProperty("alpine.worker.threads", "0");

        Assertions.assertTrue(ThreadUtil.determineNumberOfWorkerThreads() > 0);
    }

}
