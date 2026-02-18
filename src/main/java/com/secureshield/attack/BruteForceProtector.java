package com.secureshield.attack;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory brute force protector with temporary account lock.
 */
public class BruteForceProtector {

    private record AttemptState(int failures, long lockedUntilEpochMs) {
    }

    private final int maxAttempts;
    private final long lockDurationMs;
    private final Map<String, AttemptState> stateByPrincipal = new ConcurrentHashMap<>();

    public BruteForceProtector(int maxAttempts, long lockDurationMs) {
        this.maxAttempts = Math.max(1, maxAttempts);
        this.lockDurationMs = Math.max(1_000, lockDurationMs);
    }

    public boolean isLocked(String principal) {
        AttemptState state = stateByPrincipal.get(principal);
        if (state == null) {
            return false;
        }

        long now = System.currentTimeMillis();
        if (state.lockedUntilEpochMs() > now) {
            return true;
        }

        if (state.lockedUntilEpochMs() > 0) {
            stateByPrincipal.remove(principal);
        }
        return false;
    }

    public void registerFailure(String principal) {
        stateByPrincipal.compute(principal, (k, current) -> {
            long now = System.currentTimeMillis();
            int failures = (current == null || current.lockedUntilEpochMs() > 0) ? 1 : current.failures() + 1;

            if (failures >= maxAttempts) {
                return new AttemptState(0, now + lockDurationMs);
            }
            return new AttemptState(failures, 0);
        });
    }

    public void registerSuccess(String principal) {
        stateByPrincipal.remove(principal);
    }
}
