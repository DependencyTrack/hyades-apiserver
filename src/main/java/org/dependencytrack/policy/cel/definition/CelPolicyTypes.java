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
package org.dependencytrack.policy.cel.definition;

import com.google.api.expr.v1alpha1.Type;
import org.dependencytrack.proto.policy.v1.Component;
import org.dependencytrack.proto.policy.v1.License;
import org.dependencytrack.proto.policy.v1.Project;
import org.dependencytrack.proto.policy.v1.Tools;
import org.dependencytrack.proto.policy.v1.VersionDistance;
import org.dependencytrack.proto.policy.v1.Vulnerability;
import org.projectnessie.cel.checker.Decls;

public class CelPolicyTypes {

    public static final Type TYPE_COMPONENT = Decls.newObjectType(Component.getDescriptor().getFullName());
    public static final Type TYPE_LICENSE = Decls.newObjectType(License.getDescriptor().getFullName());
    public static final Type TYPE_LICENSE_GROUP = Decls.newObjectType(License.Group.getDescriptor().getFullName());
    public static final Type TYPE_PROJECT = Decls.newObjectType(Project.getDescriptor().getFullName());
    public static final Type TYPE_PROJECT_METADATA = Decls.newObjectType(Project.Metadata.getDescriptor().getFullName());
    public static final Type TYPE_PROJECT_PROPERTY = Decls.newObjectType(Project.Property.getDescriptor().getFullName());
    public static final Type TYPE_TOOLS = Decls.newObjectType(Tools.getDescriptor().getFullName());
    public static final Type TYPE_VULNERABILITY = Decls.newObjectType(Vulnerability.getDescriptor().getFullName());
    public static final Type TYPE_VULNERABILITIES = Decls.newListType(TYPE_VULNERABILITY);
    public static final Type TYPE_VULNERABILITY_ALIAS = Decls.newObjectType(Vulnerability.Alias.getDescriptor().getFullName());
    public static final Type TYPE_VERSION_DISTANCE = Decls.newObjectType(VersionDistance.getDescriptor().getFullName());

}
