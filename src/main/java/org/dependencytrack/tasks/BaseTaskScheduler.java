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
                    EventService.getInstance().publish(event);
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
