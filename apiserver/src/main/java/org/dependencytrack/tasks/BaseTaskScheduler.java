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
import alpine.common.logging.Logger;
import alpine.event.framework.Event;
import alpine.event.framework.EventService;
import com.asahaf.javacron.Schedule;
import org.dependencytrack.common.ConfigKey;

import java.util.Map;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.TimeUnit;

public abstract class BaseTaskScheduler {

    private static final Logger LOGGER = Logger.getLogger(BaseTaskScheduler.class);

    private Timer timer;

    private long pollingIntervalInMillis;

    protected void scheduleTask(Map<Event, Schedule> eventScheduleMap) {
        pollingIntervalInMillis = Config.getInstance().getPropertyAsLong(ConfigKey.TASK_SCHEDULER_POLLING_INTERVAL);
        long initialDelay = Config.getInstance().getPropertyAsLong(ConfigKey.TASK_SCHEDULER_INITIAL_DELAY);
        timer = new Timer();
        timer.schedule(new ScheduleEvent().eventScheduleMap(eventScheduleMap), initialDelay, pollingIntervalInMillis);
    }

    /**
     * Inner-class that when run() publishes an Event
     */
    private class ScheduleEvent extends TimerTask {

        private Map<Event, Schedule> eventScheduleMap;

        public ScheduleEvent eventScheduleMap(final Map<Event, Schedule> eventScheduleMap) {
            this.eventScheduleMap = eventScheduleMap;
            return this;
        }

        /**
         * Publishes the Event specified in the constructor.
         * This method publishes to all {@link EventService}s.
         */
        public void run() {
            this.eventScheduleMap.forEach((event, schedule) -> {
                long timeToExecuteTask = schedule.nextDuration(TimeUnit.MILLISECONDS);
                LOGGER.debug("Time in milliseconds to execute " + event + "is: " + timeToExecuteTask);
                if (timeToExecuteTask <= pollingIntervalInMillis) {
                    Event.dispatch(event);
                }
            });
        }
    }

    /**
     * Shuts town the TaskScheduler by canceling all scheduled events.
     */
    public void shutdown() {
        timer.cancel();
    }
}
