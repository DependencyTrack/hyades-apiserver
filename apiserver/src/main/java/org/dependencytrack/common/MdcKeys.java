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
package org.dependencytrack.common;

/**
 * Common fields for use with SLF4J's {@link org.slf4j.MDC}.
 */
public final class MdcKeys {

    public static final String MDC_BOM_FORMAT = "bomFormat";
    public static final String MDC_BOM_SERIAL_NUMBER = "bomSerialNumber";
    public static final String MDC_BOM_SPEC_VERSION = "bomSpecVersion";
    public static final String MDC_BOM_UPLOAD_TOKEN = "bomUploadToken";
    public static final String MDC_BOM_VERSION = "bomVersion";
    public static final String MDC_COMPONENT_UUID = "componentUuid";
    public static final String MDC_EVENT_TOKEN = "eventToken";
    public static final String MDC_EXTENSION = "extension";
    public static final String MDC_EXTENSION_NAME = "extensionName";
    public static final String MDC_EXTENSION_POINT = "extensionPoint";
    public static final String MDC_EXTENSION_POINT_NAME = "extensionPointName";
    public static final String MDC_KAFKA_RECORD_TOPIC = "kafkaRecordTopic";
    public static final String MDC_KAFKA_RECORD_PARTITION = "kafkaRecordPartition";
    public static final String MDC_KAFKA_RECORD_OFFSET = "kafkaRecordOffset";
    public static final String MDC_KAFKA_RECORD_KEY = "kafkaRecordKey";
    public static final String MDC_PLUGIN = "plugin";
    public static final String MDC_PROJECT_NAME = "projectName";
    public static final String MDC_PROJECT_UUID = "projectUuid";
    public static final String MDC_PROJECT_VERSION = "projectVersion";
    public static final String MDC_SCAN_TOKEN = "scanToken";

    private MdcKeys() {
    }

}
