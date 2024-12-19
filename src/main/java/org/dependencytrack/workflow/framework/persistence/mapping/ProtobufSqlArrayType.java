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
package org.dependencytrack.workflow.framework.persistence.mapping;

import com.google.protobuf.Message;
import org.jdbi.v3.core.array.SqlArrayType;

import static org.postgresql.util.PGbytea.toPGString;

abstract class ProtobufSqlArrayType<T extends Message> implements SqlArrayType<T> {

    @Override
    public String getTypeName() {
        return "BYTEA";
    }

    @Override
    public Object convertArrayElement(final T element) {
        if (element == null) {
            return null;
        }

        // https://github.com/jdbi/jdbi/issues/2109
        return toPGString(element.toByteArray());
    }

}
