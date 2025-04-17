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

import java.util.Date;

public class ComponentProjection {
    public static FieldMapping ID_FIELD_MAPPING = new FieldMapping("id", /* protoFieldName */ null, "ID");
    public long id;

    @MappedField(sqlColumnName = "UUID")
    public String uuid;

    @MappedField(sqlColumnName = "GROUP")
    public String group;

    @MappedField(sqlColumnName = "NAME")
    public String name;

    @MappedField(sqlColumnName = "VERSION")
    public String version;

    @MappedField(sqlColumnName = "CLASSIFIER")
    public String classifier;

    @MappedField(sqlColumnName = "CPE")
    public String cpe;

    @MappedField(sqlColumnName = "PURL")
    public String purl;

    @MappedField(protoFieldName = "swid_tag_id", sqlColumnName = "SWIDTAGID")
    public String swidTagId;

    @MappedField(protoFieldName = "is_internal", sqlColumnName = "INTERNAL")
    public Boolean internal;

    @MappedField(sqlColumnName = "MD5")
    public String md5;

    @MappedField(sqlColumnName = "SHA1")
    public String sha1;

    @MappedField(sqlColumnName = "SHA_256")
    public String sha256;

    @MappedField(sqlColumnName = "SHA_384")
    public String sha384;

    @MappedField(sqlColumnName = "SHA_512")
    public String sha512;

    @MappedField(sqlColumnName = "SHA3_256")
    public String sha3_256;

    @MappedField(sqlColumnName = "SHA3_384")
    public String sha3_384;

    @MappedField(sqlColumnName = "SHA3_512")
    public String sha3_512;

    @MappedField(sqlColumnName = "BLAKE2B_256")
    public String blake2b_256;

    @MappedField(sqlColumnName = "BLAKE2B_384")
    public String blake2b_384;

    @MappedField(sqlColumnName = "BLAKE2B_512")
    public String blake2b_512;

    @MappedField(sqlColumnName = "BLAKE3")
    public String blake3;
    @MappedField(protoFieldName = "resolved_license", sqlColumnName = "LICENSE_ID")
    public Long resolvedLicenseId;

    @MappedField(protoFieldName = "license_name", sqlColumnName = "LICENSE")
    public String licenseName;

    public Date publishedAt;

    public String latestVersion;
    @MappedField(protoFieldName = "license_expression", sqlColumnName = "LICENSE_EXPRESSION")
    public String licenseExpression;

}
