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
package org.dependencytrack.storage;

import org.dependencytrack.persistence.jdbi.BomDao;

import java.time.Duration;
import java.util.UUID;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

/**
 * @since 5.6.0
 */
public class DatabaseBomUploadStorageProvider implements BomUploadStorageProvider {

    @Override
    public void storeBom(final UUID token, final byte[] bom) {
        useJdbiTransaction(handle -> handle.attach(BomDao.class).createUpload(token, bom));
    }

    @Override
    public byte[] getBomByToken(final UUID token) {
        return withJdbiHandle(handle -> handle.attach(BomDao.class).getUploadByToken(token));
    }

    @Override
    public boolean deleteBomByToken(final UUID token) {
        return inJdbiTransaction(handle -> handle.attach(BomDao.class).deleteUploadByToken(token));
    }

    @Override
    public int deleteBomsForRetentionDuration(final Duration duration) {
        return inJdbiTransaction(handle -> handle.attach(BomDao.class).deleteAllUploadsForRetentionDuration(duration));
    }

}
