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
package org.dependencytrack.workflow.framework;

import org.dependencytrack.workflow.framework.failure.ApplicationFailureException;

import java.security.SecureRandom;
import java.util.Optional;

public class FaultInjectingActivityRunner<A, R> implements ActivityRunner<A, R> {

    private final ActivityRunner<A, R> delegate;
    private final SecureRandom random;

    public FaultInjectingActivityRunner(final ActivityRunner<A, R> delegate, final SecureRandom random) {
        this.delegate = delegate;
        this.random = random;
    }

    @Override
    public Optional<R> run(final ActivityRunContext<A> ctx) throws Exception {
        if (random.nextDouble() < 0.1) {
            Thread.sleep(random.nextInt(10, 1000));

            if (random.nextDouble() < 0.3) {
                throw new ApplicationFailureException("Oh no, this looks permanently broken!", null, true);
            }

            throw new IllegalStateException("I have the feeling this might resolve soon!");
        }

        return delegate.run(ctx);
    }

    ActivityRunner<A, R> delegate() {
        return delegate;
    }

}
