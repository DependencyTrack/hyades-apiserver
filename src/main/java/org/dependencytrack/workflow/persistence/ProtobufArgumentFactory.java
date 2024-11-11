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
package org.dependencytrack.workflow.persistence;

import com.google.protobuf.Message;
import org.jdbi.v3.core.argument.AbstractArgumentFactory;
import org.jdbi.v3.core.argument.Argument;
import org.jdbi.v3.core.config.ConfigRegistry;

import java.sql.Types;

abstract class ProtobufArgumentFactory<T extends Message> extends AbstractArgumentFactory<T> {

    ProtobufArgumentFactory() {
        super(Types.LONGVARBINARY);
    }

    @Override
    protected Argument build(final T value, final ConfigRegistry config) {
        return (position, statement, ctx) -> {
            if (value == null) {
                statement.setNull(position, Types.LONGVARBINARY);
                return;
            }

            // TODO: Test if compressing this with zstd has a positive
            //  impact on storage requirements and DB latencies.
            final byte[] valueBytes = value.toByteArray();
            statement.setBytes(position, valueBytes);
        };
    }
}
