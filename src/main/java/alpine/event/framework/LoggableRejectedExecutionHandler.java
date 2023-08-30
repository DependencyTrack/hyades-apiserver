package alpine.event.framework;


import alpine.common.logging.Logger;

import java.util.concurrent.RejectedExecutionHandler;
import java.util.concurrent.ThreadPoolExecutor;

public class LoggableRejectedExecutionHandler implements RejectedExecutionHandler {

    private final Logger logger;

    public LoggableRejectedExecutionHandler(final Logger logger) {
        this.logger = logger;
    }

    @Override
    public void rejectedExecution(final Runnable r, final ThreadPoolExecutor executor) {
        if (executor.isTerminated()) {
            logger.warn("A task could not be executed because the executor is already terminated");
        } else if (executor.isTerminating()) {
            logger.warn("A task could not be executed because the executor is in the process of terminating");
        } else if (executor.isShutdown()) {
            logger.warn("A task could not be executed because the executor has been shut down");
        } else {
            logger.warn("A task could not be executed for an unexpected reason");
        }
    }

}
