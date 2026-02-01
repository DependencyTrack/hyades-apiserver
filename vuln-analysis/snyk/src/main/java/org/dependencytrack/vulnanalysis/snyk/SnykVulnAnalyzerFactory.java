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
package org.dependencytrack.vulnanalysis.snyk;

import org.dependencytrack.plugin.api.ExtensionContext;
import org.dependencytrack.vulnanalysis.api.VulnAnalyzer;
import org.dependencytrack.vulnanalysis.api.VulnAnalyzerFactory;
import org.dependencytrack.vulnanalysis.api.VulnAnalyzerRequirement;

import java.util.EnumSet;

final class SnykVulnAnalyzerFactory implements VulnAnalyzerFactory {

    @Override
    public String extensionName() {
        return "snyk";
    }

    @Override
    public Class<? extends VulnAnalyzer> extensionClass() {
        return SnykVulnAnalyzer.class;
    }

    @Override
    public void init(ExtensionContext ctx) {
    }

    @Override
    public VulnAnalyzer create() {
        return new SnykVulnAnalyzer();
    }

    @Override
    public boolean isEnabled() {
        return false;
    }

    @Override
    public EnumSet<VulnAnalyzerRequirement> analyzerRequirements() {
        return EnumSet.of(VulnAnalyzerRequirement.COMPONENT_PURL);
    }

}
