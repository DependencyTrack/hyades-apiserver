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
package org.dependencytrack.tasks;

public enum LockName {
    PORTFOLIO_METRICS_TASK_LOCK,
    LDAP_SYNC_TASK_LOCK,
    EPSS_MIRROR_TASK_LOCK,
    VULNERABILITY_METRICS_TASK_LOCK,
    INTERNAL_COMPONENT_IDENTIFICATION_TASK_LOCK,
    WORKFLOW_STEP_CLEANUP_TASK_LOCK,
    PORTFOLIO_REPO_META_ANALYSIS_TASK_LOCK,
    PORTFOLIO_VULN_ANALYSIS_TASK_LOCK,
    INTEGRITY_META_INITIALIZER_LOCK,
    VULNERABILITY_POLICY_BUNDLE_FETCH_TASK_LOCK
}
