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
package org.dependencytrack.policy.cel.mapping;

public class LicenseProjection {

    public static FieldMapping ID_FIELD_MAPPING = new FieldMapping("id", /* protoFieldName */ null, "ID");

    public long id;

    @MappedField(sqlColumnName = "UUID")
    public String uuid;

    @MappedField(protoFieldName = "id", sqlColumnName = "LICENSEID")
    public String licenseId;

    @MappedField(sqlColumnName = "NAME")
    public String name;

    @MappedField(protoFieldName = "is_osi_approved", sqlColumnName = "ISOSIAPPROVED")
    public Boolean isOsiApproved;

    @MappedField(protoFieldName = "is_fsf_libre", sqlColumnName = "FSFLIBRE")
    public Boolean isFsfLibre;

    @MappedField(protoFieldName = "is_deprecated_id", sqlColumnName = "ISDEPRECATED")
    public Boolean isDeprecatedId;

    @MappedField(protoFieldName = "is_custom", sqlColumnName = "ISCUSTOMLICENSE")
    public Boolean isCustomLicense;

    public String licenseGroupsJson;

}
