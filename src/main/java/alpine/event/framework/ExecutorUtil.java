package alpine.event.framework;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.ThreadPoolExecutor;

public final class ExecutorUtil {

    public record ExecutorStats(boolean terminated, Integer queueSize, Integer activeThreads) {
    }

    private ExecutorUtil() {
    }

    public static ExecutorStats getExecutorStats(final ExecutorService executor) {
        if (executor instanceof final ThreadPoolExecutor tpExecutor) {
            return new ExecutorStats(tpExecutor.isTerminated(), tpExecutor.getQueue().size(), tpExecutor.getActiveCount());
        } else if (executor instanceof final ForkJoinPool fjpExecutor) {
            return new ExecutorStats(fjpExecutor.isTerminated(), fjpExecutor.getQueuedSubmissionCount(), fjpExecutor.getActiveThreadCount());
        }

        return new ExecutorStats(executor.isTerminated(), null, null);
    }

}
