package org.dependencytrack.tasks;

import alpine.common.logging.Logger;
import alpine.event.framework.Event;
import alpine.event.framework.EventService;
import alpine.event.framework.SingleThreadedEventService;
import com.asahaf.javacron.Schedule;

import java.util.Map;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.TimeUnit;

public abstract class BaseTaskScheduler {

    private static final Logger LOGGER = Logger.getLogger(BaseTaskScheduler.class);

    private Timer timer;

    private static final long POLLING_INTERVAL_IN_MILLIS = 10000;

    protected void scheduleTask(Map<Event, Schedule> eventScheduleMap) {
        timer = new Timer();
        timer.schedule(new ScheduleEvent().eventScheduleMap(eventScheduleMap), 100, 10000);
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
                LOGGER.debug("Time in milliseconds to execute task " + timeToExecuteTask);
                if (timeToExecuteTask <= POLLING_INTERVAL_IN_MILLIS) {
                    EventService.getInstance().publish(event);
                    SingleThreadedEventService.getInstance().publish(event);
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
