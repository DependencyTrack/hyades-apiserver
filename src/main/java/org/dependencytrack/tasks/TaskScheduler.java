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

import alpine.Config;
import alpine.common.util.BooleanUtil;
import alpine.event.LdapSyncEvent;
import alpine.event.framework.Event;
import alpine.model.ConfigProperty;
import com.asahaf.javacron.InvalidExpressionException;
import com.asahaf.javacron.Schedule;
import org.dependencytrack.common.ConfigKey;
import org.dependencytrack.event.DefectDojoUploadEventAbstract;
import org.dependencytrack.event.EpssMirrorEvent;
import org.dependencytrack.event.FortifySscUploadEventAbstract;
import org.dependencytrack.event.GitHubAdvisoryMirrorEvent;
import org.dependencytrack.event.HouseKeepingEvent;
import org.dependencytrack.event.IntegrityMetaInitializerEvent;
import org.dependencytrack.event.InternalComponentIdentificationEvent;
import org.dependencytrack.event.KennaSecurityUploadEventAbstract;
import org.dependencytrack.event.NistMirrorEvent;
import org.dependencytrack.event.OsvMirrorEvent;
import org.dependencytrack.event.PortfolioMetricsUpdateEvent;
import org.dependencytrack.event.PortfolioRepositoryMetaAnalysisEvent;
import org.dependencytrack.event.PortfolioVulnerabilityAnalysisEvent;
import org.dependencytrack.event.VulnerabilityMetricsUpdateEvent;
import org.dependencytrack.event.VulnerabilityPolicyFetchEvent;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.persistence.QueryManager;

import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.dependencytrack.common.ConfigKey.CRON_EXPRESSION_FOR_COMPONENT_IDENTIFICATION_TASK;
import static org.dependencytrack.common.ConfigKey.CRON_EXPRESSION_FOR_EPSS_MIRRORING_TASK;
import static org.dependencytrack.common.ConfigKey.CRON_EXPRESSION_FOR_GITHUB_MIRRORING_TASK;
import static org.dependencytrack.common.ConfigKey.CRON_EXPRESSION_FOR_HOUSEKEEPING_TASK;
import static org.dependencytrack.common.ConfigKey.CRON_EXPRESSION_FOR_INTEGRITY_META_INITIALIZER_TASK;
import static org.dependencytrack.common.ConfigKey.CRON_EXPRESSION_FOR_LDAP_SYNC_TASK;
import static org.dependencytrack.common.ConfigKey.CRON_EXPRESSION_FOR_NIST_MIRRORING_TASK;
import static org.dependencytrack.common.ConfigKey.CRON_EXPRESSION_FOR_OSV_MIRRORING_TASK;
import static org.dependencytrack.common.ConfigKey.CRON_EXPRESSION_FOR_PORTFOLIO_METRICS_TASK;
import static org.dependencytrack.common.ConfigKey.CRON_EXPRESSION_FOR_REPO_META_ANALYSIS_TASK;
import static org.dependencytrack.common.ConfigKey.CRON_EXPRESSION_FOR_VULNERABILITY_METRICS_TASK;
import static org.dependencytrack.common.ConfigKey.CRON_EXPRESSION_FOR_VULNERABILITY_POLICY_BUNDLE_FETCH_TASK;
import static org.dependencytrack.common.ConfigKey.CRON_EXPRESSION_FOR_VULN_ANALYSIS_TASK;
import static org.dependencytrack.model.ConfigPropertyConstants.DEFECTDOJO_ENABLED;
import static org.dependencytrack.model.ConfigPropertyConstants.FORTIFY_SSC_ENABLED;
import static org.dependencytrack.model.ConfigPropertyConstants.KENNA_ENABLED;

/**
 * @author Steve Springett
 * @since 3.0.0
 */
public final class TaskScheduler extends BaseTaskScheduler {

    // Holds an instance of TaskScheduler
    private static final TaskScheduler INSTANCE = new TaskScheduler();

    /**
     * Private constructor.
     */
    private TaskScheduler() {
        final Config configInstance = Config.getInstance();
        try {
            Map<Event, Schedule> configurableTasksMap = new HashMap<>();
            Map<Event, Schedule> eventScheduleMap = Map.ofEntries(
                    Map.entry(new VulnerabilityPolicyFetchEvent(), Schedule.create(configInstance.getProperty(CRON_EXPRESSION_FOR_VULNERABILITY_POLICY_BUNDLE_FETCH_TASK))),
                    Map.entry(new LdapSyncEvent(), Schedule.create(configInstance.getProperty(CRON_EXPRESSION_FOR_LDAP_SYNC_TASK))),
                    Map.entry(new NistMirrorEvent(), Schedule.create(configInstance.getProperty(CRON_EXPRESSION_FOR_NIST_MIRRORING_TASK))),
                    Map.entry(new OsvMirrorEvent(null), Schedule.create(configInstance.getProperty(CRON_EXPRESSION_FOR_OSV_MIRRORING_TASK))),
                    Map.entry(new GitHubAdvisoryMirrorEvent(), Schedule.create(configInstance.getProperty(CRON_EXPRESSION_FOR_GITHUB_MIRRORING_TASK))),
                    Map.entry(new EpssMirrorEvent(), Schedule.create(configInstance.getProperty(CRON_EXPRESSION_FOR_EPSS_MIRRORING_TASK))),
                    Map.entry(new PortfolioMetricsUpdateEvent(), Schedule.create(configInstance.getProperty(CRON_EXPRESSION_FOR_PORTFOLIO_METRICS_TASK))),
                    Map.entry(new VulnerabilityMetricsUpdateEvent(), Schedule.create(configInstance.getProperty(CRON_EXPRESSION_FOR_VULNERABILITY_METRICS_TASK))),
                    Map.entry(new InternalComponentIdentificationEvent(), Schedule.create(configInstance.getProperty(CRON_EXPRESSION_FOR_COMPONENT_IDENTIFICATION_TASK))),
                    Map.entry(new PortfolioVulnerabilityAnalysisEvent(), Schedule.create(configInstance.getProperty(CRON_EXPRESSION_FOR_VULN_ANALYSIS_TASK))),
                    Map.entry(new PortfolioRepositoryMetaAnalysisEvent(), Schedule.create(configInstance.getProperty(CRON_EXPRESSION_FOR_REPO_META_ANALYSIS_TASK))),
                    Map.entry(new IntegrityMetaInitializerEvent(), Schedule.create(configInstance.getProperty(CRON_EXPRESSION_FOR_INTEGRITY_META_INITIALIZER_TASK))),
                    Map.entry(new HouseKeepingEvent(), Schedule.create(configInstance.getProperty(CRON_EXPRESSION_FOR_HOUSEKEEPING_TASK)))
            );

            if (isTaskEnabled(FORTIFY_SSC_ENABLED)) {
                configurableTasksMap.put(new FortifySscUploadEventAbstract(), Schedule.create(configInstance.getProperty(ConfigKey.CRON_EXPRESSION_FOR_FORTIFY_SSC_SYNC)));
            }
            if (isTaskEnabled(DEFECTDOJO_ENABLED)) {
                configurableTasksMap.put(new DefectDojoUploadEventAbstract(), Schedule.create(configInstance.getProperty(ConfigKey.CRON_EXPRESSION_FOR_DEFECT_DOJO_SYNC)));
            }
            if (isTaskEnabled(KENNA_ENABLED)) {
                configurableTasksMap.put(new KennaSecurityUploadEventAbstract(), Schedule.create(configInstance.getProperty(ConfigKey.CRON_EXPRESSION_FOR_KENNA_SYNC)));
            }

            Map<Event, Schedule> mergedEventScheduleMap = Stream.concat(eventScheduleMap.entrySet().stream(), configurableTasksMap.entrySet().stream())
                    .collect(Collectors.toMap(
                            Map.Entry::getKey,
                            Map.Entry::getValue));

            scheduleTask(mergedEventScheduleMap);

        } catch (InvalidExpressionException invalidExpressionException) {
            throw new RuntimeException("Cron expression cannot be parsed to schedule tasks", invalidExpressionException);
        }
    }

    /**
     * Return an instance of the TaskScheduler instance.
     *
     * @return a TaskScheduler instance
     */
    public static TaskScheduler getInstance() {
        return INSTANCE;
    }

    private boolean isTaskEnabled(final ConfigPropertyConstants enabledConstraint) {
        try (QueryManager qm = new QueryManager()) {
            final ConfigProperty enabledProperty = qm.getConfigProperty(
                    enabledConstraint.getGroupName(), enabledConstraint.getPropertyName());
            if (enabledProperty != null && enabledProperty.getPropertyValue() != null) {
                final boolean isEnabled = BooleanUtil.valueOf(enabledProperty.getPropertyValue());
                if (!isEnabled) {
                    return false;
                }
            } else {
                return false;
            }
            return true;
        }
    }
}
